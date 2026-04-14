package utils

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func ComputeEpochDataHash(data *structures.NextEpochData) string {
	raw, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	return Blake3(string(raw))
}

func BuildEpochRotationProofSigningPayload(
	epochId int,
	nextEpochId int,
	epochDataHash string,
	finishedOnHeight int64,
	finishedOnBlockId string,
	finishedOnHash string,
) string {
	return strings.Join([]string{
		"EPOCH_ROTATION_PROOF",
		strconv.Itoa(epochId),
		strconv.Itoa(nextEpochId),
		epochDataHash,
		strconv.FormatInt(finishedOnHeight, 10),
		finishedOnBlockId,
		finishedOnHash,
	}, ":")
}

func VerifyAggregatedEpochRotationProof(proof *structures.AggregatedEpochRotationProof) bool {
	if proof == nil || len(proof.Proofs) == 0 || proof.EpochDataHash == "" {
		return false
	}

	if proof.NextEpochId != proof.EpochId+1 || proof.FinishedOnHeight < -1 || proof.FinishedOnHash == "" {
		return false
	}

	recomputedHash := ComputeEpochDataHash(&proof.EpochData)
	if recomputedHash == "" || recomputedHash != proof.EpochDataHash {
		return false
	}

	epochData := LoadCoreEpochData(proof.EpochId)
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

	dataToVerify := BuildEpochRotationProofSigningPayload(
		proof.EpochId,
		proof.NextEpochId,
		proof.EpochDataHash,
		proof.FinishedOnHeight,
		proof.FinishedOnBlockId,
		proof.FinishedOnHash,
	)

	okSignatures := 0
	seen := make(map[string]bool)

	for pubKey, signature := range proof.Proofs {
		if quorumMap[pubKey] && !seen[pubKey] {
			if cryptography.VerifySignature(dataToVerify, pubKey, signature) {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}

	return okSignatures >= majority
}
