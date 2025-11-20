package structures

import (
	"encoding/json"
	"fmt"
)

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

type AnchorRotationProofBundle struct {
	EpochIndex int               `json:"epochIndex"`
	Creator    string            `json:"creator"`
	VotingStat VotingStat        `json:"votingStat"`
	Signatures map[string]string `json:"signatures"`
}

type LeaderFinalizationProofBundle struct {
	ChainId    string            `json:"chainId"`
	Leader     string            `json:"leader"`
	VotingStat VotingStat        `json:"votingStat"`
	Signatures map[string]string `json:"signatures"`
}

type BlockExtraData struct {
	Fields                   map[string]string               `json:"fields,omitempty"`
	RotationProofs           []AnchorRotationProofBundle     `json:"rotationProofs,omitempty"`
	LeaderFinalizationProofs []LeaderFinalizationProofBundle `json:"leaderFinalizationProofs,omitempty"`
}

type blockExtraDataAlias struct {
	Fields                   map[string]string               `json:"fields,omitempty"`
	RotationProofs           []AnchorRotationProofBundle     `json:"rotationProofs,omitempty"`
	LeaderFinalizationProofs []LeaderFinalizationProofBundle `json:"leaderFinalizationProofs,omitempty"`
}

func (extra BlockExtraData) MarshalJSON() ([]byte, error) {
	if len(extra.RotationProofs) == 0 && len(extra.LeaderFinalizationProofs) == 0 {
		if len(extra.Fields) == 0 {
			return []byte("{}"), nil
		}
		return json.Marshal(extra.Fields)
	}
	alias := blockExtraDataAlias(extra)
	if alias.Fields == nil {
		alias.Fields = map[string]string{}
	}
	return json.Marshal(alias)
}

func (extra *BlockExtraData) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*extra = BlockExtraData{}
		return nil
	}
	var alias blockExtraDataAlias
	if err := json.Unmarshal(data, &alias); err == nil && (alias.Fields != nil || alias.RotationProofs != nil || alias.LeaderFinalizationProofs != nil) {
		*extra = BlockExtraData(alias)
		return nil
	}
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err == nil {
		extra.Fields = fields
		extra.RotationProofs = nil
		extra.LeaderFinalizationProofs = nil
		return nil
	}
	return fmt.Errorf("invalid extraData payload")
}

type AcceptExtraDataRequest struct {
	RotationProofs []AnchorRotationProofBundle `json:"rotationProofs"`
}

type AcceptExtraDataResponse struct {
	Accepted int `json:"accepted"`
}

type AcceptLeaderFinalizationDataRequest struct {
	LeaderFinalizations []LeaderFinalizationProofBundle `json:"leaderFinalizations"`
}
