package utils

import (
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func VerifyAggregatedFinalizationProof(proof *structures.AggregatedFinalizationProof, epochHandler *structures.EpochDataHandler) bool {

	epochIndex := strconv.Itoa(epochHandler.Id)

	dataThatShouldBeSigned := strings.Join([]string{proof.PrevBlockHash, proof.BlockId, proof.BlockHash, epochIndex}, ":")

	majority := GetQuorumMajority(epochHandler)

	okSignatures := 0

	seen := make(map[string]bool)

	quorumMap := make(map[string]bool)

	for _, pk := range epochHandler.Quorum {
		quorumMap[pk] = true
	}

	for pubKey, signature := range proof.Proofs {

		if cryptography.VerifySignature(dataThatShouldBeSigned, pubKey, signature) {

			if quorumMap[pubKey] && !seen[pubKey] {
				seen[pubKey] = true
				okSignatures++
			}
		}
	}

	return okSignatures >= majority
}
