package utils

import (
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func VerifyAggregatedFinalizationProof(proof *structures.AggregatedFinalizationProof, epochHandler *structures.EpochDataHandler) bool {

	epochIndex := strconv.Itoa(epochHandler.Id)

	dataThatShouldBeSigned := strings.Join([]string{proof.PrevBlockHash, proof.BlockId, proof.BlockHash, epochIndex}, ":")

	majority := GetQuorumMajority(epochHandler)

	return HasVerifiedQuorumSignatures(proof.Proofs, QuorumMap(epochHandler.Quorum), dataThatShouldBeSigned, majority)
}
