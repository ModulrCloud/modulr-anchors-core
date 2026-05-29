package utils

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/constants"
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

func BuildEpochAnnouncementProofSigningPayload(
	epochId int,
	nextEpochId int,
	epochDataHash string,
) string {
	return strings.Join([]string{
		constants.SigningPrefixEpochAnnouncement,
		strconv.Itoa(epochId),
		strconv.Itoa(nextEpochId),
		epochDataHash,
	}, ":")
}

func VerifyAggregatedEpochRotationProof(proof *structures.AggregatedEpochRotationProof) bool {
	if proof == nil {
		return false
	}

	epochData := LoadCoreEpochData(proof.EpochId)
	return VerifyAggregatedEpochRotationProofAgainstEpoch(proof, epochData)
}

func VerifyAggregatedEpochRotationProofAgainstEpoch(proof *structures.AggregatedEpochRotationProof, epochData *structures.CoreEpochData) bool {
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

	if epochData == nil || len(epochData.Quorum) == 0 {
		return false
	}
	if proof.EpochId != epochData.EpochId {
		return false
	}

	majority := (2*len(epochData.Quorum))/3 + 1
	if majority > len(epochData.Quorum) {
		majority = len(epochData.Quorum)
	}

	quorumMap := QuorumMap(epochData.Quorum)

	dataToVerify := BuildEpochRotationProofSigningPayload(
		proof.EpochId,
		proof.NextEpochId,
		proof.EpochDataHash,
		proof.FinishedOnHeight,
		proof.FinishedOnBlockId,
		proof.FinishedOnHash,
	)

	return HasVerifiedQuorumSignatures(proof.Proofs, quorumMap, dataToVerify, majority)
}

func VerifyAggregatedEpochAnnouncementProof(proof *structures.AggregatedEpochAnnouncementProof) bool {
	if proof == nil {
		return false
	}

	epochData := LoadCoreEpochData(proof.EpochId)
	return VerifyAggregatedEpochAnnouncementProofAgainstEpoch(proof, epochData)
}

func VerifyAggregatedEpochAnnouncementProofAgainstEpoch(proof *structures.AggregatedEpochAnnouncementProof, epochData *structures.CoreEpochData) bool {
	if proof == nil || len(proof.Proofs) == 0 || proof.EpochDataHash == "" {
		return false
	}

	if proof.NextEpochId != proof.EpochId+1 {
		return false
	}

	recomputedHash := ComputeEpochDataHash(&proof.EpochData)
	if recomputedHash == "" || recomputedHash != proof.EpochDataHash {
		return false
	}

	if epochData == nil || len(epochData.Quorum) == 0 || proof.EpochId != epochData.EpochId {
		return false
	}

	majority := (2*len(epochData.Quorum))/3 + 1
	if majority > len(epochData.Quorum) {
		majority = len(epochData.Quorum)
	}

	quorumMap := QuorumMap(epochData.Quorum)
	dataToVerify := BuildEpochAnnouncementProofSigningPayload(
		proof.EpochId,
		proof.NextEpochId,
		proof.EpochDataHash,
	)

	return HasVerifiedQuorumSignatures(proof.Proofs, quorumMap, dataToVerify, majority)
}
