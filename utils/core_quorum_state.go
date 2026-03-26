package utils

import (
	"encoding/json"
	"fmt"
	"sort"
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

func InitCoreQuorumStateFromGenesis() *structures.CoreQuorumState {

	existing := LoadCoreQuorumState()

	if existing != nil {
		return existing
	}

	quorum := ComputeCoreQuorumFromGenesis()
	epochHash := ComputeCoreInitialEpochHash()

	epochData := &structures.CoreEpochData{
		EpochId:   0,
		EpochHash: epochHash,
		Quorum:    quorum,
	}

	PersistCoreEpochData(epochData)

	state := &structures.CoreQuorumState{
		LatestEpochId: 0,
	}

	PersistCoreQuorumState(state)

	return state
}

// ApplyCoreQuorumRotation verifies and applies a quorum rotation, storing the new
// epoch data and advancing the latest epoch pointer. Returns true on success.
// If there is a gap between the current state and the attestation, it returns false
// (use CatchUpCoreQuorumRotations to fill the gap first).
func ApplyCoreQuorumRotation(attestation *structures.QuorumRotationAttestation) bool {

	state := LoadCoreQuorumState()
	if state == nil {
		return false
	}

	if attestation.EpochId != state.LatestEpochId {
		return false
	}

	currentEpochData := LoadCoreEpochData(state.LatestEpochId)
	if currentEpochData == nil {
		return false
	}

	if !VerifyQuorumRotationAttestation(attestation, currentEpochData.Quorum) {
		return false
	}

	newEpochData := &structures.CoreEpochData{
		EpochId:   attestation.NextEpochId,
		EpochHash: attestation.NextEpochHash,
		Quorum:    attestation.NextQuorum,
	}

	PersistCoreEpochData(newEpochData)

	state.LatestEpochId = attestation.NextEpochId
	PersistCoreQuorumState(state)

	cleanupOldCoreEpochData(state.LatestEpochId)

	return true
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

		if !verifyCoreAfp(&proof.VotingStat.Afp, epochData, epochFullID, quorumMap, majority) {
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

func verifyCoreAfp(afp *structures.AggregatedFinalizationProof, epochData *structures.CoreEpochData, epochFullID string, quorumMap map[string]bool, majority int) bool {

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

func VerifyQuorumRotationAttestation(attestation *structures.QuorumRotationAttestation, currentQuorum []string) bool {

	if attestation == nil || len(currentQuorum) == 0 {
		return false
	}

	majority := (2*len(currentQuorum))/3 + 1
	if majority > len(currentQuorum) {
		majority = len(currentQuorum)
	}

	quorumMap := make(map[string]bool, len(currentQuorum))
	for _, pk := range currentQuorum {
		quorumMap[pk] = true
	}

	sortedNextQuorum := make([]string, len(attestation.NextQuorum))
	copy(sortedNextQuorum, attestation.NextQuorum)
	sort.Strings(sortedNextQuorum)

	dataToVerify := "QUORUM_ROTATION:" + strconv.Itoa(attestation.EpochId) + ":" + strconv.Itoa(attestation.NextEpochId) + ":" + attestation.NextEpochHash + ":" + strings.Join(sortedNextQuorum, ",")

	okSignatures := 0
	seen := make(map[string]bool)

	for pubKey, signature := range attestation.Proofs {
		if quorumMap[pubKey] && !seen[pubKey] {
			if cryptography.VerifySignature(dataToVerify, pubKey, signature) {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}

	return okSignatures >= majority
}

// CatchUpCoreQuorumRotations fills the gap between the anchor's current core epoch
// and the target epoch by sequentially fetching and applying quorum rotations from
// the core PoD. The fetchFn parameter is the function that retrieves a
// QuorumRotationAttestation for a given epoch ID from the core PoD.
// Returns the number of epochs successfully applied.
func CatchUpCoreQuorumRotations(targetEpochId int, fetchFn func(epochId int) *structures.QuorumRotationAttestation) int {

	applied := 0

	for {
		state := LoadCoreQuorumState()
		if state == nil {
			break
		}

		if state.LatestEpochId >= targetEpochId {
			break
		}

		attestation := fetchFn(state.LatestEpochId)
		if attestation == nil {
			LogWithTime(
				fmt.Sprintf("Core quorum catch-up: failed to fetch rotation for epoch %d from core PoD", state.LatestEpochId),
				YELLOW_COLOR,
			)
			break
		}

		if !ApplyCoreQuorumRotation(attestation) {
			LogWithTime(
				fmt.Sprintf("Core quorum catch-up: failed to apply rotation for epoch %d -> %d", attestation.EpochId, attestation.NextEpochId),
				YELLOW_COLOR,
			)
			break
		}

		applied++
		LogWithTime(
			fmt.Sprintf("Core quorum catch-up: applied rotation epoch %d -> %d", attestation.EpochId, attestation.NextEpochId),
			CYAN_COLOR,
		)
	}

	return applied
}
