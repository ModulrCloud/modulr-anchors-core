package block_pack

import (
	"encoding/json"
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

type ExtraDataToBlock struct {
	Rest                     map[string]string                    `json:"rest,omitempty"`
	RotationProofs           []structures.AnchorRotationProof     `json:"rotationProofs,omitempty"`
	LeaderFinalizationProofs []structures.LeaderFinalizationProof `json:"leaderFinalizationProofs,omitempty"`
}

type blockExtraDataAlias struct {
	Rest                     map[string]string                    `json:"rest,omitempty"`
	RotationProofs           []structures.AnchorRotationProof     `json:"rotationProofs,omitempty"`
	LeaderFinalizationProofs []structures.LeaderFinalizationProof `json:"leaderFinalizationProofs,omitempty"`
}

func (extra ExtraDataToBlock) MarshalJSON() ([]byte, error) {
	if len(extra.RotationProofs) == 0 && len(extra.LeaderFinalizationProofs) == 0 {
		if len(extra.Rest) == 0 {
			return []byte("{}"), nil
		}
		return json.Marshal(extra.Rest)
	}
	alias := blockExtraDataAlias(extra)
	if alias.Rest == nil {
		alias.Rest = map[string]string{}
	}
	return json.Marshal(alias)
}

func (extra *ExtraDataToBlock) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		*extra = ExtraDataToBlock{}
		return nil
	}
	var alias blockExtraDataAlias
	if err := json.Unmarshal(data, &alias); err == nil && (alias.Rest != nil || alias.RotationProofs != nil || alias.LeaderFinalizationProofs != nil) {
		*extra = ExtraDataToBlock(alias)
		return nil
	}
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err == nil {
		extra.Rest = fields
		extra.RotationProofs = nil
		extra.LeaderFinalizationProofs = nil
		return nil
	}
	return fmt.Errorf("invalid extraData payload")
}
