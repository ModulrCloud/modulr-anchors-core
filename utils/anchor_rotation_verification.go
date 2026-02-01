package utils

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func BuildAnchorRotationProofPayload(anchor string, blockIndex int, blockHash string, epochIndex int) string {

	return fmt.Sprintf("ANCHOR_ROTATION_PROOF:%s:%d:%s:%d", anchor, blockIndex, blockHash, epochIndex)
}

func VerifyAggregatedAnchorRotationProof(proof *structures.AggregatedAnchorRotationProof, epochHandler *structures.EpochDataHandler) error {

	if proof.VotingStat.Afp.BlockId == "" {
		return fmt.Errorf("missing AFP blockId")
	}
	if !slices.Contains(epochHandler.AnchorsRegistry, proof.Anchor) {
		return fmt.Errorf("anchor %s not found in epoch %d", proof.Anchor, epochHandler.Id)
	}
	expectedBlockId := fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
	if proof.VotingStat.Afp.BlockId != expectedBlockId {
		return fmt.Errorf("AFP blockId mismatch")
	}
	if proof.VotingStat.Hash != proof.VotingStat.Afp.BlockHash {
		return fmt.Errorf("AFP block hash mismatch")
	}

	blockParts := strings.Split(proof.VotingStat.Afp.BlockId, ":")

	afpIndex, err := strconv.Atoi(blockParts[2])

	if err != nil || afpIndex != proof.VotingStat.Index {
		return fmt.Errorf("AFP index mismatch")
	}

	dataToVerify := BuildAnchorRotationProofPayload(proof.Anchor, proof.VotingStat.Index, proof.VotingStat.Hash, proof.EpochIndex)

	quorum := epochHandler.Quorum
	verified := 0
	seen := make(map[string]struct{})
	for voter, signature := range proof.Signatures {
		if signature == "" {
			continue
		}
		if _, dup := seen[voter]; dup {
			continue
		}
		if !slices.Contains(quorum, voter) {
			continue
		}
		if !cryptography.VerifySignature(dataToVerify, voter, signature) {
			continue
		}
		seen[voter] = struct{}{}
		verified++
	}

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
		if !strings.EqualFold(p.Anchor, rotatedAnchor) {
			continue
		}
		if err := VerifyAggregatedAnchorRotationProof(&p, epochHandler); err == nil {
			return true
		}
	}
	return false
}
