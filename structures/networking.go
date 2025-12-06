package structures

type QuorumMemberData struct {
	PubKey, Url string
}

type AnchorRotationProofRequest struct {
	EpochIndex int        `json:"epochIndex"`
	Creator    string     `json:"creator"`
	Proposal   VotingStat `json:"proposal"`
}

type AnchorRotationProofResponse struct {
	Status     string      `json:"status"`
	Message    string      `json:"message,omitempty"`
	Signature  string      `json:"signature,omitempty"`
	VotingStat *VotingStat `json:"votingStat,omitempty"`
}

type AcceptAggregatedAnchorRotationProofRequest struct {
	AggregatedRotationProofs []AggregatedAnchorRotationProof `json:"aggregatedAnchorRotationProofs"`
}

type AcceptAnchorRotationProofResponse struct {
	Accepted int `json:"accepted"`
}

type AcceptLeaderFinalizationProofRequest struct {
	LeaderFinalizations []AggregatedLeaderFinalizationProof `json:"leaderFinalizations"`
}
