package utils

import (
	"fmt"
	"slices"

	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func BuildAnchorRotationProofPayload(anchor string, blockIndex int, blockHash string, epochIndex int) string {

	return fmt.Sprintf("ANCHOR_ROTATION_PROOF:%s:%d:%s:%d", anchor, blockIndex, blockHash, epochIndex)
}

func VerifyAggregatedAnchorRotationProof(proof *structures.AggregatedAnchorRotationProof, epochHandler *structures.EpochDataHandler) error {

	if !slices.Contains(epochHandler.AnchorsRegistry, proof.Anchor) {
		return fmt.Errorf("anchor %s not found in epoch %d", proof.Anchor, epochHandler.Id)
	}

	if proof.VotingStat.Index == -1 {
		if proof.VotingStat.Hash != constants.ZeroHash {
			return fmt.Errorf("empty voting stat hash mismatch")
		}
		if proof.VotingStat.Afp.BlockId != "" {
			return fmt.Errorf("empty voting stat must not include AFP")
		}
		return verifyAnchorRotationProofSignatures(proof, epochHandler)
	}

	if proof.VotingStat.Afp.BlockId == "" {
		return fmt.Errorf("missing AFP blockId")
	}
	expectedBlockId := FormatBlockID(proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
	if proof.VotingStat.Afp.BlockId != expectedBlockId {
		return fmt.Errorf("AFP blockId mismatch")
	}
	if proof.VotingStat.Hash != proof.VotingStat.Afp.BlockHash {
		return fmt.Errorf("AFP block hash mismatch")
	}

	blockID, err := ParseBlockID(proof.VotingStat.Afp.BlockId)
	if err != nil || blockID.Index != proof.VotingStat.Index {
		return fmt.Errorf("AFP index mismatch")
	}

	return verifyAnchorRotationProofSignatures(proof, epochHandler)
}

func verifyAnchorRotationProofSignatures(proof *structures.AggregatedAnchorRotationProof, epochHandler *structures.EpochDataHandler) error {
	dataToVerify := BuildAnchorRotationProofPayload(proof.Anchor, proof.VotingStat.Index, proof.VotingStat.Hash, proof.EpochIndex)

	verified := CountVerifiedQuorumSignatures(proof.Signatures, QuorumMap(epochHandler.Quorum), dataToVerify)

	majority := GetQuorumMajority(epochHandler)
	if verified < majority {
		return fmt.Errorf("verified signatures %d < %d", verified, majority)
	}
	return nil
}

func HasValidAggregatedAnchorRotationProof(proofs []structures.AggregatedAnchorRotationProof, rotatedAnchor string, epochHandler *structures.EpochDataHandler) bool {
	if epochHandler == nil || rotatedAnchor == "" {
		return false
	}
	for _, p := range proofs {
		if p.Anchor != rotatedAnchor {
			continue
		}
		if err := VerifyAggregatedAnchorRotationProof(&p, epochHandler); err == nil {
			return true
		}
	}
	return false
}
