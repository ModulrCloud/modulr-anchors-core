// Package threads — AlfpCollectionThread.
//
// Background:
//
//	The historical pipeline for ALFP delivery is one-directional:
//	  modulr-core LeaderFinalizationThread (LFT) opens WS connections to its own
//	  quorum, collects per-leader signatures into AggregatedLeaderFinalizationProof
//	  (ALFP), and POSTs the result to every anchor over HTTP.
//
//	If LFT falls behind even by one epoch (any cause: validator restart,
//	long block-execution stall, network blip), ALFP POSTs land on anchors
//	whose epoch window has already moved past the proof's epoch. The anchor
//	rejects them and never hears about that epoch's ALFPs again. Block
//	generation on the anchor side then halts because the protocol requires
//	ALFP inclusion.
//
//	This thread closes that gap by letting the anchor itself collect ALFPs
//	directly from the core quorum — exactly the way LFT does on the core
//	side — but only when LFT is observably late (per-leader grace period
//	after the leadership window ends).
//
// What this thread does on each tick:
//   - For every CoreEpochData in the supported window:
//   - For every leader whose leadership-window+grace has elapsed:
//   - Skip if ALFP already in mempool / already included in a generated block.
//   - Try the unified PoD first (cheapest path: somebody else may have
//     already aggregated it).
//   - If PoD doesn't have it, fan out WS requests to that core epoch's
//     quorum (using URLs from CORE_GENESIS + CORE_BOOTSTRAP_NODES HTTP
//     resolution), handle OK/UPGRADE responses, converge on a SkipData,
//     and once 2/3+1 OK signatures are gathered build the ALFP, verify
//     it, and add it to the mempool.
//
// Connections to the core quorum are reused per (anchor, core-epoch) and
// closed when the core epoch leaves the supported window.
package threads

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/gorilla/websocket"
)

// alfpCollectionTickInterval is the cadence at which the thread scans the
// supported core epochs for missing ALFPs.
const alfpCollectionTickInterval = 2 * time.Second

// alfpCollectionLftGraceMs is the additional time the anchor waits past the
// end of a leader's leadership window before attempting collection. The grace
// gives modulr-core's LFT a fair chance to deliver the ALFP via the normal
// POST path; only if LFT is clearly late do we step in.
const alfpCollectionLftGraceMs int64 = 3000

// alfpCollectionPodFetchInterval throttles how often we ask the unified PoD
// for the same (epoch, leader) ALFP before falling back to manual collection.
const alfpCollectionPodFetchInterval = time.Second

// alfpCollectionRequestTimeout caps a single request/response round to the
// core quorum. Multiple rounds may happen back-to-back as SkipData converges
// via UPGRADE responses.
const alfpCollectionRequestTimeout = 3 * time.Second

// leaderCollectionCache mirrors LeaderFinalizationCache from modulr-core.
// It tracks the converging SkipData and the per-voter signatures collected
// for a single (epoch, leader) pair.
type leaderCollectionCache struct {
	skipData     structures.VotingStat
	proofs       map[string]string
	lastPodFetch time.Time
}

// epochCollectionState holds the long-lived WS connections + per-leader caches
// for a single core epoch.
type epochCollectionState struct {
	epochId       int
	epochHash     string
	quorum        []string
	leaders       []string
	wsConns       map[string]*websocket.Conn
	guards        *utils.WebsocketGuards
	waiter        *utils.QuorumWaiter
	caches        map[string]*leaderCollectionCache
	urlByPubkey   map[string]string
	connectedOnce bool
}

var (
	alfpCollectionMu     sync.Mutex
	alfpCollectionStates = make(map[int]*epochCollectionState)
	// alfpCollectionInFlight prevents two ticks from running collection for
	// the same (epoch, leader) concurrently.
	alfpCollectionInFlight = make(map[string]struct{})
)

func AlfpCollectionThread() {
	ticker := time.NewTicker(alfpCollectionTickInterval)
	defer ticker.Stop()

	for range ticker.C {
		runAlfpCollectionTick()
	}
}

func runAlfpCollectionTick() {
	state := utils.LoadCoreQuorumState()
	if state == nil {
		return
	}

	supportedEpochs := loadSupportedCoreEpochs(state.LatestEpochId)
	if len(supportedEpochs) == 0 {
		return
	}

	pruneStaleEpochCollectionStates(supportedEpochs)

	for _, epochData := range supportedEpochs {
		processCoreEpochCollection(epochData)
	}
}

// loadSupportedCoreEpochs returns CoreEpochData for every core epoch currently
// inside the anchor's supported window, ordered from oldest to newest.
func loadSupportedCoreEpochs(latest int) []*structures.CoreEpochData {
	result := make([]*structures.CoreEpochData, 0)
	for epochId := 0; epochId <= latest; epochId++ {
		if data := utils.LoadCoreEpochData(epochId); data != nil {
			result = append(result, data)
		}
	}
	return result
}

// pruneStaleEpochCollectionStates closes WS connections and drops cached state
// for any core epoch that has dropped out of the supported window since the
// previous tick.
func pruneStaleEpochCollectionStates(active []*structures.CoreEpochData) {
	activeIds := make(map[int]struct{}, len(active))
	for _, e := range active {
		activeIds[e.EpochId] = struct{}{}
	}

	alfpCollectionMu.Lock()
	defer alfpCollectionMu.Unlock()

	for epochId, st := range alfpCollectionStates {
		if _, ok := activeIds[epochId]; ok {
			continue
		}
		closeEpochCollectionStateLocked(st)
		delete(alfpCollectionStates, epochId)
	}
}

func closeEpochCollectionStateLocked(st *epochCollectionState) {
	if st == nil {
		return
	}
	if st.guards != nil {
		st.guards.ConnMu.Lock()
		for id, c := range st.wsConns {
			if c != nil {
				_ = c.Close()
				utils.ScheduleWriteMuCleanup(st.guards, c)
			}
			delete(st.wsConns, id)
		}
		st.guards.ConnMu.Unlock()
	}
}

func processCoreEpochCollection(epochData *structures.CoreEpochData) {
	if epochData == nil || len(epochData.LeadersSequence) == 0 || len(epochData.Quorum) == 0 {
		return
	}

	leaderEndTimestamps := computeLeaderEndTimestamps(epochData.EpochId, len(epochData.LeadersSequence))
	if len(leaderEndTimestamps) == 0 {
		return
	}

	now := utils.GetUTCTimestampInMilliSeconds()

	pendingLeaders := make([]int, 0)
	for idx, leader := range epochData.LeadersSequence {
		if utils.IsAlfpIncluded(epochData.EpochId, leader) {
			continue
		}
		if globals.MEMPOOL.HasLeaderFinalizationProof(epochData.EpochId, leader) {
			continue
		}
		if now < leaderEndTimestamps[idx]+alfpCollectionLftGraceMs {
			continue
		}
		pendingLeaders = append(pendingLeaders, idx)
	}

	if len(pendingLeaders) == 0 {
		return
	}

	st := ensureEpochCollectionState(epochData)
	if st == nil {
		return
	}

	for _, leaderIdx := range pendingLeaders {
		tryCollectLeaderAlfp(st, leaderIdx)
	}
}

// computeLeaderEndTimestamps returns the absolute end timestamp (UTC ms) of
// each leadership window in the core epoch. Mirrors modulr-core's
// `leaderTimeIsOut` formula:
//
//	leaderEnd[i] = epochStart + (i+1) * leadershipDuration
//
// epochStart is computed from CORE_GENESIS as
//
//	firstEpochStart + epochId * epochDuration
//
// which is exact as long as core-network parameters haven't drifted from
// genesis (currently the case on this network).
func computeLeaderEndTimestamps(epochId int, leadersCount int) []int64 {
	if leadersCount <= 0 {
		return nil
	}

	params := globals.CORE_GENESIS.NetworkParameters
	if params.EpochDuration <= 0 || params.LeadershipDuration <= 0 {
		return nil
	}

	firstStart := int64(globals.CORE_GENESIS.FirstEpochStartTimestamp)
	epochStart := firstStart + int64(epochId)*params.EpochDuration

	out := make([]int64, leadersCount)
	for i := 0; i < leadersCount; i++ {
		out[i] = epochStart + int64(i+1)*params.LeadershipDuration
	}
	return out
}

// ensureEpochCollectionState returns the cached state for `epochData.EpochId`
// or creates a fresh one (resolves URLs, opens WS connections). Connections
// are kept open across ticks until the epoch is pruned.
func ensureEpochCollectionState(epochData *structures.CoreEpochData) *epochCollectionState {
	alfpCollectionMu.Lock()
	if existing, ok := alfpCollectionStates[epochData.EpochId]; ok {
		alfpCollectionMu.Unlock()
		return existing
	}
	alfpCollectionMu.Unlock()

	urlByPubkey := utils.ResolveCoreValidatorWsUrls(epochData.Quorum)
	if len(urlByPubkey) == 0 {
		utils.LogWithTimeThrottled(
			fmt.Sprintf("alfp_collection:no_urls:%d", epochData.EpochId),
			15*time.Second,
			fmt.Sprintf("ALFP collection: no WSS URLs resolvable for any quorum member of core epoch %d (genesis empty, bootstraps unreachable?)", epochData.EpochId),
			utils.YELLOW_COLOR,
		)
		return nil
	}

	guards := utils.NewWebsocketGuards()
	st := &epochCollectionState{
		epochId:     epochData.EpochId,
		epochHash:   epochData.EpochHash,
		quorum:      append([]string(nil), epochData.Quorum...),
		leaders:     append([]string(nil), epochData.LeadersSequence...),
		wsConns:     make(map[string]*websocket.Conn),
		guards:      guards,
		waiter:      utils.NewQuorumWaiter(len(epochData.Quorum), guards),
		caches:      make(map[string]*leaderCollectionCache),
		urlByPubkey: urlByPubkey,
	}
	utils.OpenWebsocketConnectionsWithUrlMap(st.quorum, st.urlByPubkey, st.wsConns, st.guards)
	st.connectedOnce = true

	alfpCollectionMu.Lock()
	if existing, ok := alfpCollectionStates[epochData.EpochId]; ok {
		// Lost the race; drop our freshly opened conns and reuse existing.
		closeEpochCollectionStateLocked(st)
		alfpCollectionMu.Unlock()
		return existing
	}
	alfpCollectionStates[epochData.EpochId] = st
	alfpCollectionMu.Unlock()

	utils.LogWithTime(
		fmt.Sprintf("ALFP collection: opened %d/%d WS connections to core quorum of epoch %d", len(st.wsConns), len(st.quorum), st.epochId),
		utils.CYAN_COLOR,
	)

	return st
}

func ensureLeaderCacheLocked(st *epochCollectionState, leaderIdx int) *leaderCollectionCache {
	leader := st.leaders[leaderIdx]
	cache, ok := st.caches[leader]
	if ok {
		return cache
	}
	cache = &leaderCollectionCache{
		skipData: structures.NewVotingStatTemplate(),
		proofs:   make(map[string]string),
	}
	st.caches[leader] = cache
	return cache
}

func tryCollectLeaderAlfp(st *epochCollectionState, leaderIdx int) {
	leaderPubKey := st.leaders[leaderIdx]
	inFlightKey := fmt.Sprintf("%d:%s", st.epochId, leaderPubKey)

	alfpCollectionMu.Lock()
	if _, busy := alfpCollectionInFlight[inFlightKey]; busy {
		alfpCollectionMu.Unlock()
		return
	}
	alfpCollectionInFlight[inFlightKey] = struct{}{}
	cache := ensureLeaderCacheLocked(st, leaderIdx)
	alfpCollectionMu.Unlock()

	defer func() {
		alfpCollectionMu.Lock()
		delete(alfpCollectionInFlight, inFlightKey)
		alfpCollectionMu.Unlock()
	}()

	// Re-check under the in-flight guard: another tick may have just landed it.
	if utils.IsAlfpIncluded(st.epochId, leaderPubKey) {
		return
	}
	if globals.MEMPOOL.HasLeaderFinalizationProof(st.epochId, leaderPubKey) {
		return
	}

	// Cheap path: ask the unified PoD first. Throttled so we don't hammer it
	// while LFT is still aggregating.
	if tryAcceptAlfpFromPoD(st.epochId, leaderPubKey, cache) {
		return
	}

	// Re-establish dropped WS connections lazily before each round so that a
	// transient validator restart doesn't disable collection forever.
	reopenMissingCoreQuorumConnections(st)

	majority := coreQuorumMajority(len(st.quorum))
	epochFullID := st.epochHash + "#" + strconv.Itoa(st.epochId)

	alfpCollectionMu.Lock()
	skipData := cache.skipData
	alfpCollectionMu.Unlock()

	request := struct {
		Route                   string                `json:"route"`
		EpochIndex              int                   `json:"epochIndex"`
		IndexOfLeaderToFinalize int                   `json:"indexOfLeaderToFinalize"`
		SkipData                structures.VotingStat `json:"skipData"`
	}{
		Route:                   constants.WsRouteGetLeaderFinalizationProof,
		EpochIndex:              st.epochId,
		IndexOfLeaderToFinalize: leaderIdx,
		SkipData:                skipData,
	}

	message, err := json.Marshal(request)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), alfpCollectionRequestTimeout)
	defer cancel()

	validate := buildLeaderFinalizationValidator(st, leaderPubKey, skipData, epochFullID)

	responses, ok := st.waiter.SendAndWaitValidated(ctx, message, st.quorum, st.wsConns, majority, validate)
	if !ok {
		utils.LogWithTimeThrottled(
			fmt.Sprintf("alfp_collection:no_majority:%d:%s", st.epochId, leaderPubKey),
			5*time.Second,
			fmt.Sprintf("ALFP collection: failed to gather majority from core quorum (epoch=%d leader=%s quorum=%d majority=%d)", st.epochId, leaderPubKey, len(st.quorum), majority),
			utils.YELLOW_COLOR,
		)
		return
	}

	for voter, raw := range responses {
		applyLeaderFinalizationResponse(st, leaderPubKey, epochFullID, voter, raw)
	}

	alfpCollectionMu.Lock()
	gotEnough := len(cache.proofs) >= majority
	alfpCollectionMu.Unlock()

	if !gotEnough {
		return
	}

	finalizeAndDepositAlfp(st, leaderPubKey, cache)
}

func tryAcceptAlfpFromPoD(epochId int, leader string, cache *leaderCollectionCache) bool {
	alfpCollectionMu.Lock()
	due := time.Since(cache.lastPodFetch) > alfpCollectionPodFetchInterval
	if due {
		cache.lastPodFetch = time.Now()
	}
	alfpCollectionMu.Unlock()

	if !due {
		return false
	}

	proof := websocket_pack.GetAggregatedLeaderFinalizationProofFromPoD(epochId, leader)
	if proof == nil {
		return false
	}
	if proof.EpochIndex != epochId || proof.Leader != leader {
		return false
	}
	if !utils.VerifyCoreAlfp(proof) {
		return false
	}

	globals.MEMPOOL.AddAggregatedLeaderFinalizationProof(*proof)

	utils.LogWithTime(
		fmt.Sprintf("ALFP collection: accepted ALFP from PoD (epoch=%d leader=%s)", epochId, leader),
		utils.GREEN_COLOR,
	)
	return true
}

func reopenMissingCoreQuorumConnections(st *epochCollectionState) {
	st.guards.ConnMu.RLock()
	missing := make([]string, 0)
	for _, pk := range st.quorum {
		if c, ok := st.wsConns[pk]; !ok || c == nil {
			missing = append(missing, pk)
		}
	}
	st.guards.ConnMu.RUnlock()

	if len(missing) == 0 {
		return
	}

	for _, pk := range missing {
		url := st.urlByPubkey[pk]
		if url == "" {
			// Validator URL not in cache yet — try a fresh resolution. This is
			// useful when CoreBootstrapNodes only became reachable after
			// startup.
			resolved := utils.ResolveCoreValidatorWsUrls([]string{pk})
			url = resolved[pk]
			if url != "" {
				st.urlByPubkey[pk] = url
			}
		}
		if url == "" {
			continue
		}
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			continue
		}
		st.guards.ConnMu.Lock()
		st.wsConns[pk] = conn
		st.guards.ConnMu.Unlock()
	}
}

func coreQuorumMajority(quorumSize int) int {
	if quorumSize <= 0 {
		return 0
	}
	majority := (2*quorumSize)/3 + 1
	if majority > quorumSize {
		majority = quorumSize
	}
	return majority
}

// buildLeaderFinalizationValidator returns a closure compatible with
// QuorumWaiter.SendAndWaitValidated. It validates that responses come from
// quorum members and either bear a verifiable signature on `expectedSkipData`
// (status=OK) or a verifiable AFP for an UPGRADE skipData (status=UPGRADE).
func buildLeaderFinalizationValidator(st *epochCollectionState, leaderPubKey string, expectedSkipData structures.VotingStat, epochFullID string) func(string, []byte) bool {
	quorumMap := make(map[string]bool, len(st.quorum))
	for _, pk := range st.quorum {
		quorumMap[pk] = true
	}

	return func(_ string, raw []byte) bool {
		var holder map[string]any
		if json.Unmarshal(raw, &holder) != nil {
			return false
		}
		status, _ := holder["status"].(string)

		switch status {
		case "OK":
			var resp struct {
				Voter           string `json:"voter"`
				ForLeaderPubkey string `json:"forLeaderPubkey"`
				Sig             string `json:"sig"`
			}
			if json.Unmarshal(raw, &resp) != nil {
				return false
			}
			if resp.ForLeaderPubkey != leaderPubKey || !quorumMap[resp.Voter] {
				return false
			}
			data := strings.Join([]string{
				constants.SigningPrefixLeaderFinalization,
				leaderPubKey,
				strconv.Itoa(expectedSkipData.Index),
				expectedSkipData.Hash,
				epochFullID,
			}, ":")
			return cryptography.VerifySignature(data, resp.Voter, resp.Sig)

		case "UPGRADE":
			var resp struct {
				Voter           string                `json:"voter"`
				ForLeaderPubkey string                `json:"forLeaderPubkey"`
				SkipData        structures.VotingStat `json:"skipData"`
			}
			if json.Unmarshal(raw, &resp) != nil {
				return false
			}
			if resp.ForLeaderPubkey != leaderPubKey || !quorumMap[resp.Voter] {
				return false
			}
			return validateUpgradeSkipData(resp.SkipData, st.epochId, leaderPubKey, epochFullID, quorumMap)

		default:
			return false
		}
	}
}

func validateUpgradeSkipData(skip structures.VotingStat, epochId int, leaderPubKey, epochFullID string, quorumMap map[string]bool) bool {
	if skip.Index < 0 {
		return true
	}
	parts := strings.Split(skip.Afp.BlockId, ":")
	if len(parts) != 3 {
		return false
	}
	indexFromId, err := strconv.Atoi(parts[2])
	if err != nil || indexFromId != skip.Index || parts[0] != strconv.Itoa(epochId) || parts[1] != leaderPubKey {
		return false
	}
	if skip.Hash != skip.Afp.BlockHash {
		return false
	}

	majority := coreQuorumMajority(len(quorumMap))
	dataToVerify := strings.Join([]string{skip.Afp.PrevBlockHash, skip.Afp.BlockId, skip.Afp.BlockHash, epochFullID}, ":")

	okSignatures := 0
	seen := make(map[string]bool)
	for pubKey, signature := range skip.Afp.Proofs {
		if quorumMap[pubKey] && !seen[pubKey] {
			if cryptography.VerifySignature(dataToVerify, pubKey, signature) {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}
	return okSignatures >= majority
}

func applyLeaderFinalizationResponse(st *epochCollectionState, leaderPubKey, epochFullID, voter string, raw []byte) {
	var holder map[string]any
	if json.Unmarshal(raw, &holder) != nil {
		return
	}
	status, _ := holder["status"].(string)

	switch status {
	case "OK":
		var resp struct {
			Voter           string `json:"voter"`
			ForLeaderPubkey string `json:"forLeaderPubkey"`
			Sig             string `json:"sig"`
		}
		if json.Unmarshal(raw, &resp) != nil {
			return
		}
		if resp.ForLeaderPubkey != leaderPubKey {
			return
		}

		quorumMap := make(map[string]bool, len(st.quorum))
		for _, pk := range st.quorum {
			quorumMap[pk] = true
		}
		if !quorumMap[resp.Voter] {
			return
		}

		alfpCollectionMu.Lock()
		cache := st.caches[leaderPubKey]
		if cache == nil {
			alfpCollectionMu.Unlock()
			return
		}
		skipData := cache.skipData
		alfpCollectionMu.Unlock()

		dataToVerify := strings.Join([]string{
			constants.SigningPrefixLeaderFinalization,
			leaderPubKey,
			strconv.Itoa(skipData.Index),
			skipData.Hash,
			epochFullID,
		}, ":")
		if !cryptography.VerifySignature(dataToVerify, resp.Voter, resp.Sig) {
			return
		}

		alfpCollectionMu.Lock()
		cache.proofs[resp.Voter] = resp.Sig
		alfpCollectionMu.Unlock()

	case "UPGRADE":
		var resp struct {
			Voter           string                `json:"voter"`
			ForLeaderPubkey string                `json:"forLeaderPubkey"`
			SkipData        structures.VotingStat `json:"skipData"`
		}
		if json.Unmarshal(raw, &resp) != nil {
			return
		}
		if resp.ForLeaderPubkey != leaderPubKey {
			return
		}

		quorumMap := make(map[string]bool, len(st.quorum))
		for _, pk := range st.quorum {
			quorumMap[pk] = true
		}
		if !validateUpgradeSkipData(resp.SkipData, st.epochId, leaderPubKey, epochFullID, quorumMap) {
			return
		}

		alfpCollectionMu.Lock()
		cache := st.caches[leaderPubKey]
		if cache == nil {
			alfpCollectionMu.Unlock()
			return
		}
		// Only adopt strictly higher skip data: prevents a stale UPGRADE from
		// overwriting an already-converged-on value within the same round.
		if resp.SkipData.Index > cache.skipData.Index {
			cache.skipData = resp.SkipData
			cache.proofs = make(map[string]string)
		}
		alfpCollectionMu.Unlock()

		_ = voter
	}
}

func finalizeAndDepositAlfp(st *epochCollectionState, leaderPubKey string, cache *leaderCollectionCache) {
	alfpCollectionMu.Lock()
	proofsCopy := make(map[string]string, len(cache.proofs))
	for v, s := range cache.proofs {
		proofsCopy[v] = s
	}
	skipData := cache.skipData
	alfpCollectionMu.Unlock()

	aggregated := structures.AggregatedLeaderFinalizationProof{
		EpochIndex: st.epochId,
		Leader:     leaderPubKey,
		VotingStat: structures.VotingStat{
			Index: skipData.Index,
			Hash:  skipData.Hash,
			Afp:   skipData.Afp,
		},
		Signatures: proofsCopy,
	}

	if !utils.VerifyCoreAlfp(&aggregated) {
		// Should not happen: validate() already filtered each signature against
		// the same quorum/skipData. Fail loud so the bug is visible.
		utils.LogWithTimeThrottled(
			fmt.Sprintf("alfp_collection:self_verify_failed:%d:%s", st.epochId, leaderPubKey),
			10*time.Second,
			fmt.Sprintf("ALFP collection: self-built ALFP failed VerifyCoreAlfp (epoch=%d leader=%s sigs=%d)", st.epochId, leaderPubKey, len(proofsCopy)),
			utils.RED_COLOR,
		)
		return
	}

	globals.MEMPOOL.AddAggregatedLeaderFinalizationProof(aggregated)

	utils.LogWithTime(
		fmt.Sprintf("ALFP collection: built ALFP locally and deposited to mempool (epoch=%d leader=%s sigs=%d index=%d)", st.epochId, leaderPubKey, len(proofsCopy), skipData.Index),
		utils.DEEP_GREEN_COLOR,
	)
}
