package structures

import "github.com/modulrcloud/modulr-anchors-core/constants"

type VotingStat struct {
	Index int                         `json:"index"`
	Hash  string                      `json:"hash"`
	Afp   AggregatedFinalizationProof `json:"afp"`
}

func NewVotingStatTemplate() VotingStat {

	return VotingStat{
		Index: -1,
		Hash:  constants.ZeroHash,
		Afp:   AggregatedFinalizationProof{},
	}

}
