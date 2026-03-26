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

	state := &structures.CoreQuorumState{
		CurrentEpochId: 0,
		CurrentQuorum:  quorum,
	}

	PersistCoreQuorumState(state)

	return state
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

	dataToVerify := "QUORUM_ROTATION:" + strconv.Itoa(attestation.EpochId) + ":" + strconv.Itoa(attestation.NextEpochId) + ":" + strings.Join(sortedNextQuorum, ",")

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
