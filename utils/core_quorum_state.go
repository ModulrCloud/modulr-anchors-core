package utils

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

const CORE_QUORUM_STATE_KEY = "CORE_QUORUM_STATE"

func coreEpochDataKey(epochId int) []byte {
	return []byte(fmt.Sprintf("CORE_EPOCH_DATA:%d", epochId))
}

func LoadCoreQuorumState() *structures.CoreQuorumState {

	raw, err := databases.EPOCH_DATA.Get([]byte(CORE_QUORUM_STATE_KEY), nil)

	if err != nil || len(raw) == 0 {
		return nil
	}

	var state structures.CoreQuorumState

	if json.Unmarshal(raw, &state) != nil {
		return nil
	}

	return &state
}

func PersistCoreQuorumState(state *structures.CoreQuorumState) {

	if raw, err := json.Marshal(state); err == nil {
		_ = databases.EPOCH_DATA.Put([]byte(CORE_QUORUM_STATE_KEY), raw, nil)
	}
}

func LoadCoreEpochData(epochId int) *structures.CoreEpochData {

	raw, err := databases.EPOCH_DATA.Get(coreEpochDataKey(epochId), nil)

	if err != nil || len(raw) == 0 {
		return nil
	}

	var data structures.CoreEpochData

	if json.Unmarshal(raw, &data) != nil {
		return nil
	}

	return &data
}

func PersistCoreEpochData(data *structures.CoreEpochData) {

	if raw, err := json.Marshal(data); err == nil {
		_ = databases.EPOCH_DATA.Put(coreEpochDataKey(data.EpochId), raw, nil)
	}
}

func DeleteCoreEpochData(epochId int) {
	_ = databases.EPOCH_DATA.Delete(coreEpochDataKey(epochId), nil)
}

func coreAggregatedEpochRotationProofKey(epochId int) []byte {
	return []byte(fmt.Sprintf("CORE_EPOCH_ROTATION_PROOF:%d", epochId))
}

func PersistAggregatedEpochRotationProof(proof *structures.AggregatedEpochRotationProof) {
	if raw, err := json.Marshal(proof); err == nil {
		_ = databases.EPOCH_DATA.Put(coreAggregatedEpochRotationProofKey(proof.NextEpochId), raw, nil)
	}
}

func LoadAggregatedEpochRotationProof(epochId int) *structures.AggregatedEpochRotationProof {
	raw, err := databases.EPOCH_DATA.Get(coreAggregatedEpochRotationProofKey(epochId), nil)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var proof structures.AggregatedEpochRotationProof
	if json.Unmarshal(raw, &proof) != nil {
		return nil
	}
	return &proof
}

func DeleteAggregatedEpochRotationProof(epochId int) {
	_ = databases.EPOCH_DATA.Delete(coreAggregatedEpochRotationProofKey(epochId), nil)
}

func InitCoreQuorumStateFromGenesis() *structures.CoreQuorumState {

	existing := LoadCoreQuorumState()

	if existing != nil {
		backfillGenesisLeadersSequenceIfMissing()
		return existing
	}

	quorum := ComputeCoreQuorumFromGenesis()
	epochHash := ComputeCoreInitialEpochHash()
	leadersSequence := ComputeCoreLeadersSequenceFromGenesis()

	epochData := &structures.CoreEpochData{
		EpochId:         0,
		EpochHash:       epochHash,
		Quorum:          quorum,
		LeadersSequence: leadersSequence,
	}

	PersistCoreEpochData(epochData)

	state := &structures.CoreQuorumState{
		LatestEpochId: 0,
	}

	PersistCoreQuorumState(state)

	return state
}

// ApplyCoreAggregatedEpochRotationProof verifies and applies a core epoch rotation proof,
// storing the new epoch data and advancing the active latest epoch pointer.
// Returns true on success.
func ApplyCoreAggregatedEpochRotationProof(proof *structures.AggregatedEpochRotationProof) bool {

	state := LoadCoreQuorumState()
	if state == nil {
		return false
	}

	if proof.EpochId != state.LatestEpochId {
		return false
	}

	currentEpochData := LoadCoreEpochData(state.LatestEpochId)
	if currentEpochData == nil {
		return false
	}

	if !VerifyAggregatedEpochRotationProof(proof) {
		return false
	}

	newEpochData := &structures.CoreEpochData{
		EpochId:         proof.NextEpochId,
		EpochHash:       proof.EpochData.NextEpochHash,
		Quorum:          proof.EpochData.NextEpochQuorum,
		LeadersSequence: append([]string(nil), proof.EpochData.NextEpochLeadersSequence...),
	}

	PersistCoreEpochData(newEpochData)
	PersistAggregatedEpochRotationProof(proof)

	state.LatestEpochId = proof.NextEpochId
	PersistCoreQuorumState(state)

	cleanupOldCoreEpochData(state.LatestEpochId)

	return true
}

// backfillGenesisLeadersSequenceIfMissing populates LeadersSequence for the
// genesis CoreEpochData record on anchors that were initialized before the
// LeadersSequence field was added. For non-genesis epochs there is nothing
// we can deterministically backfill from local data — the leaders sequence
// arrives via AggregatedEpochRotationProof.EpochData.NextEpochLeadersSequence
// at the next rotation.
func backfillGenesisLeadersSequenceIfMissing() {
	epochData := LoadCoreEpochData(0)
	if epochData == nil || len(epochData.LeadersSequence) > 0 {
		return
	}
	epochData.LeadersSequence = ComputeCoreLeadersSequenceFromGenesis()
	if len(epochData.LeadersSequence) == 0 {
		return
	}
	PersistCoreEpochData(epochData)
}

func cleanupOldCoreEpochData(latestEpochId int) {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	maxEpochs := handlers.APPROVEMENT_THREAD_METADATA.Handler.NetworkParameters.MaxEpochsToSupport
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	if maxEpochs <= 0 {
		maxEpochs = 1
	}

	oldestToKeep := latestEpochId - maxEpochs
	if oldestToKeep < 0 {
		return
	}

	for epochId := oldestToKeep; epochId >= 0; epochId-- {
		existing := LoadCoreEpochData(epochId)
		if existing == nil {
			break
		}
		DeleteCoreEpochData(epochId)
		DeleteAggregatedEpochRotationProof(epochId)
		// Inclusion markers are keyed by the core epoch ID and become useless
		// once the core epoch leaves the supported window.
		DeleteAlfpInclusionMarkersForEpoch(epochId)
	}
}

// VerifyCoreAlfp performs full cryptographic verification of an ALFP from modulr-core.
// It looks up the core epoch data for the ALFP's epoch, checks signatures against
// the quorum for that specific epoch, and requires 2/3+1 majority.
// It also verifies the inner AFP (VotingStat.Afp) when present.
func VerifyCoreAlfp(proof *structures.AggregatedLeaderFinalizationProof) bool {

	if proof == nil || len(proof.Signatures) == 0 {
		return false
	}

	epochData := LoadCoreEpochData(proof.EpochIndex)

	if epochData == nil || epochData.EpochHash == "" || len(epochData.Quorum) == 0 {
		return false
	}

	majority := (2*len(epochData.Quorum))/3 + 1
	if majority > len(epochData.Quorum) {
		majority = len(epochData.Quorum)
	}

	quorumMap := make(map[string]bool, len(epochData.Quorum))
	for _, pk := range epochData.Quorum {
		quorumMap[pk] = true
	}

	epochFullID := epochData.EpochHash + "#" + strconv.Itoa(epochData.EpochId)

	if proof.VotingStat.Index >= 0 {
		parts := strings.Split(proof.VotingStat.Afp.BlockId, ":")
		if len(parts) != 3 || parts[0] != strconv.Itoa(epochData.EpochId) || parts[1] != proof.Leader {
			return false
		}

		indexFromId, err := strconv.Atoi(parts[2])
		if err != nil || indexFromId != proof.VotingStat.Index || proof.VotingStat.Hash != proof.VotingStat.Afp.BlockHash {
			return false
		}

		if !verifyCoreAfp(&proof.VotingStat.Afp, epochFullID, quorumMap, majority) {
			return false
		}
	}

	dataToVerify := strings.Join([]string{
		"LEADER_FINALIZATION_PROOF",
		proof.Leader,
		strconv.Itoa(proof.VotingStat.Index),
		proof.VotingStat.Hash,
		epochFullID,
	}, ":")

	okSignatures := 0
	seen := make(map[string]bool)

	for pubKey, signature := range proof.Signatures {
		if quorumMap[pubKey] && !seen[pubKey] {
			if cryptography.VerifySignature(dataToVerify, pubKey, signature) {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}

	return okSignatures >= majority
}

func verifyCoreAfp(afp *structures.AggregatedFinalizationProof, epochFullID string, quorumMap map[string]bool, majority int) bool {

	if afp == nil {
		return false
	}

	dataThatShouldBeSigned := strings.Join([]string{afp.PrevBlockHash, afp.BlockId, afp.BlockHash, epochFullID}, ":")

	okSignatures := 0
	seen := make(map[string]bool)

	for pubKey, signature := range afp.Proofs {
		if quorumMap[pubKey] && !seen[pubKey] {
			if cryptography.VerifySignature(dataThatShouldBeSigned, pubKey, signature) {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}

	return okSignatures >= majority
}

// CatchUpCoreEpochRotationProofs fills the gap between the active core epoch
// and the target epoch by sequentially loading locally stored proofs first
// and then optionally fetching missing ones via fetchFn.
// Returns the number of epochs successfully applied.
func CatchUpCoreEpochRotationProofs(targetEpochId int, fetchFn func(epochId int) *structures.AggregatedEpochRotationProof) int {

	applied := 0

	for {
		state := LoadCoreQuorumState()
		if state == nil {
			break
		}

		if state.LatestEpochId >= targetEpochId {
			break
		}

		nextEpochId := state.LatestEpochId + 1

		proof := LoadAggregatedEpochRotationProof(nextEpochId)
		if proof == nil && fetchFn != nil {
			proof = fetchFn(state.LatestEpochId)
			if proof != nil {
				PersistAggregatedEpochRotationProof(proof)
			}
		}
		if proof == nil {
			LogWithTime(
				fmt.Sprintf("Core quorum catch-up: missing epoch rotation proof for epoch %d -> %d", state.LatestEpochId, nextEpochId),
				YELLOW_COLOR,
			)
			break
		}

		if !ApplyCoreAggregatedEpochRotationProof(proof) {
			LogWithTime(
				fmt.Sprintf("Core quorum catch-up: failed to apply epoch rotation proof for epoch %d -> %d", proof.EpochId, proof.NextEpochId),
				YELLOW_COLOR,
			)
			break
		}

		applied++
		LogWithTime(
			fmt.Sprintf("Core quorum catch-up: applied epoch rotation proof %d -> %d", proof.EpochId, proof.NextEpochId),
			CYAN_COLOR,
		)
	}

	return applied
}
