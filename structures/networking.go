package structures

import "encoding/json"

type AnchorRotationProofRequest struct {
	EpochIndex int        `json:"epochIndex"`
	ForAnchor  string     `json:"forAnchor"`
	Proposal   VotingStat `json:"proposal"`
}

type AnchorRotationProofResponse struct {
	Status     string      `json:"status"`
	Signature  string      `json:"signature,omitempty"`
	VotingStat *VotingStat `json:"votingStat,omitempty"`
}

type AcceptAggregatedAnchorRotationProofRequest struct {
	AggregatedRotationProofs []AggregatedAnchorRotationProof `json:"aggregatedAnchorRotationProofs"`
}

type AcceptLeaderFinalizationProofRequest struct {
	LeaderFinalizations []AggregatedLeaderFinalizationProof `json:"leaderFinalizations"`
}

type AcceptProofResponse struct {
	Accepted int `json:"accepted"`
}

// AarpInclusionReceipt is an optional proof-of-inclusion response for AARP delivery.
// Block is the block that included the AARP; Afp is the AFP for the *next* block (index+1),
// which proves the inclusion block is approved.
//
// We use RawMessage to avoid importing block/afp types here (would create import cycles).
type AarpInclusionReceipt struct {
	Status         string          `json:"status"` // "OK" | "PENDING"
	EpochIndex     int             `json:"epochIndex"`
	ReceiverAnchor string          `json:"receiverAnchor"`
	RotatedAnchor  string          `json:"rotatedAnchor"`
	BlockId        string          `json:"blockId,omitempty"`
	Block          json.RawMessage `json:"block,omitempty"`
	Afp            json.RawMessage `json:"afp,omitempty"`
}

type AcceptAggregatedAnchorRotationProofResponse struct {
	Accepted int                    `json:"accepted"`
	Receipts []AarpInclusionReceipt `json:"receipts,omitempty"`
}
