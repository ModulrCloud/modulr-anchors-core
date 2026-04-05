package utils

import (
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func VerifyEpochDataAttestation(attestation *structures.EpochDataAttestation) bool {
	if attestation == nil || len(attestation.Proofs) == 0 || attestation.EpochDataHash == "" {
		return false
	}

	if attestation.NextEpochId != attestation.EpochId+1 {
		return false
	}

	epochData := LoadCoreEpochData(attestation.EpochId)
	if epochData == nil || len(epochData.Quorum) == 0 {
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

	dataToVerify := strings.Join([]string{
		"EPOCH_DATA_ATTESTATION",
		strconv.Itoa(attestation.EpochId),
		strconv.Itoa(attestation.NextEpochId),
		attestation.EpochDataHash,
	}, ":")

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
