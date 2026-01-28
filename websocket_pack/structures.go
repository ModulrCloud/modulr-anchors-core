package websocket_pack

import (
	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/structures"
)

type WsFinalizationProofRequest struct {
	Route            string                                 `json:"route"`
	Block            block_pack.Block                       `json:"block"`
	PreviousBlockAfp structures.AggregatedFinalizationProof `json:"previousBlockAfp"`
}

type WsFinalizationProofResponse struct {
	Voter             string `json:"voter"`
	FinalizationProof string `json:"finalizationProof"`
	VotedForHash      string `json:"votedForHash"`
}

type WsBlockWithAfpRequest struct {
	Route   string `json:"route"`
	BlockId string `json:"blockID"`
}

type WsBlockWithAfpResponse struct {
	Block *block_pack.Block                       `json:"block"`
	Afp   *structures.AggregatedFinalizationProof `json:"afp"`
}

type WsAnchorBlockWithAfpStoreRequest struct {
	Route string                                 `json:"route"`
	Block block_pack.Block                       `json:"block"`
	Afp   structures.AggregatedFinalizationProof `json:"afp"`
}

type WsVotingStatRequest struct {
	Route      string `json:"route"`
	EpochIndex int    `json:"epochIndex"`
	Creator    string `json:"creator"`
}

type WsVotingStatResponse struct {
	Status     string                `json:"status"`
	EpochIndex int                   `json:"epochIndex"`
	Creator    string                `json:"creator"`
	VotingStat structures.VotingStat `json:"votingStat"`
	Error      string                `json:"error,omitempty"`
}
