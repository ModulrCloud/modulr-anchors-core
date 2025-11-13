package utils

import (
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

func GetQuorumMajority(epochHandler *structures.EpochDataHandler) int {

	quorumSize := len(epochHandler.Quorum)

	majority := (2 * quorumSize) / 3

	majority += 1

	if majority > quorumSize {
		return quorumSize
	}

	return majority
}

func GetQuorumUrlsAndPubkeys(epochHandler *structures.EpochDataHandler) []structures.QuorumMemberData {

	var toReturn []structures.QuorumMemberData

	for _, pubKey := range epochHandler.Quorum {

		anchorStorage := GetAnchorFromApprovementThreadState(pubKey)

		toReturn = append(toReturn, structures.QuorumMemberData{PubKey: pubKey, Url: anchorStorage.AnchorUrl})

	}

	return toReturn

}

func GetCurrentEpochQuorum(epochHandler *structures.EpochDataHandler, quorumSize int, newEpochSeed string) []string {

	futureQuorum := make([]string, len(epochHandler.AnchorsRegistry))

	copy(futureQuorum, epochHandler.AnchorsRegistry)

	return futureQuorum

}
