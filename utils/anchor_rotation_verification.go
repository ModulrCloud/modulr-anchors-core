package utils

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func VerifyAggregatedAnchorRotationProof(proof *structures.AggregatedAnchorRotationProof, epochHandler *structures.EpochDataHandler) error {

	if proof.VotingStat.Index < 0 || proof.VotingStat.Hash == "" {
		return fmt.Errorf("invalid voting stat")
	}
	if proof.VotingStat.Afp.BlockId == "" {
		return fmt.Errorf("missing AFP blockId")
	}
	expectedBlockId := fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
	if !strings.EqualFold(proof.VotingStat.Afp.BlockId, expectedBlockId) {
		return fmt.Errorf("AFP blockId mismatch")
	}
	if !strings.EqualFold(proof.VotingStat.Hash, proof.VotingStat.Afp.BlockHash) {
		return fmt.Errorf("AFP block hash mismatch")
	}
	blockParts := strings.Split(proof.VotingStat.Afp.BlockId, ":")
	if len(blockParts) != 3 {
		return fmt.Errorf("invalid AFP blockId format")
	}
	afpIndex, err := strconv.Atoi(blockParts[2])
	if err != nil || afpIndex != proof.VotingStat.Index {
		return fmt.Errorf("AFP index mismatch")
	}

	epochFullID := epochHandler.Hash + "#" + strconv.Itoa(epochHandler.Id)
	dataToVerify := strings.Join([]string{
		proof.VotingStat.Afp.PrevBlockHash,
		proof.VotingStat.Afp.BlockId,
		proof.VotingStat.Afp.BlockHash,
		epochFullID,
	}, ":")

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
