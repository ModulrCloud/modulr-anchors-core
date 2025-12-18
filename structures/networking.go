package structures

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
