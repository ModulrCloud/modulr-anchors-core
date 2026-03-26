package utils

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

const CORE_QUORUM_STATE_KEY = "CORE_QUORUM_STATE"

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

func InitCoreQuorumStateFromGenesis() *structures.CoreQuorumState {

	existing := LoadCoreQuorumState()

	if existing != nil {
		return existing
	}

	quorum := ComputeCoreQuorumFromGenesis()
	epochHash := ComputeCoreInitialEpochHash()

	state := &structures.CoreQuorumState{
		CurrentEpochId:   0,
		CurrentEpochHash: epochHash,
		CurrentQuorum:    quorum,
	}

	PersistCoreQuorumState(state)

	return state
}

// VerifyCoreAlfp performs full cryptographic verification of an ALFP from modulr-core.
// It checks that signatures are from legitimate core quorum members, verifies the
// signed data using the core epoch hash, and requires 2/3+1 majority.
func VerifyCoreAlfp(proof *structures.AggregatedLeaderFinalizationProof, coreState *structures.CoreQuorumState) bool {

	if proof == nil || coreState == nil || len(coreState.CurrentQuorum) == 0 || len(proof.Signatures) == 0 {
		return false
	}

	if coreState.CurrentEpochHash == "" {
		return false
	}

	majority := (2*len(coreState.CurrentQuorum))/3 + 1
	if majority > len(coreState.CurrentQuorum) {
		majority = len(coreState.CurrentQuorum)
	}

	quorumMap := make(map[string]bool, len(coreState.CurrentQuorum))
	for _, pk := range coreState.CurrentQuorum {
		quorumMap[pk] = true
	}

	epochFullID := coreState.CurrentEpochHash + "#" + strconv.Itoa(coreState.CurrentEpochId)

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
