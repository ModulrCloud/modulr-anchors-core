package structures

import "encoding/json"

type AggregatedFinalizationProof struct {
	PrevBlockHash string            `json:"prevBlockHash"`
	BlockId       string            `json:"blockId"`
	BlockHash     string            `json:"blockHash"`
	Proofs        map[string]string `json:"proofs"`
}

func (afp *AggregatedFinalizationProof) UnmarshalJSON(data []byte) error {

	type alias AggregatedFinalizationProof

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	*afp = AggregatedFinalizationProof(aux)

	return nil

}

func (afp AggregatedFinalizationProof) MarshalJSON() ([]byte, error) {

	type alias AggregatedFinalizationProof

	aux := alias(afp)

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	return json.Marshal(aux)
}

type AggregatedAnchorRotationProof struct {
	EpochIndex int               `json:"epochIndex"`
	Anchor     string            `json:"anchor"`
	VotingStat VotingStat        `json:"votingStat"`
	Signatures map[string]string `json:"signatures"`
}

func (aarp *AggregatedAnchorRotationProof) UnmarshalJSON(data []byte) error {

	type alias AggregatedAnchorRotationProof

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Signatures == nil {
		aux.Signatures = make(map[string]string)
	}

	*aarp = AggregatedAnchorRotationProof(aux)

	return nil

}

func (aarp AggregatedAnchorRotationProof) MarshalJSON() ([]byte, error) {

	type alias AggregatedAnchorRotationProof

	aux := alias(aarp)

	if aux.Signatures == nil {
		aux.Signatures = make(map[string]string)
	}

	return json.Marshal(aux)
}

type AggregatedLeaderFinalizationProof struct {
	EpochIndex int               `json:"epochIndex"`
	Leader     string            `json:"leader"`
	VotingStat VotingStat        `json:"votingStat"`
	Signatures map[string]string `json:"signatures"`
}

func (alfp *AggregatedLeaderFinalizationProof) UnmarshalJSON(data []byte) error {

	type alias AggregatedLeaderFinalizationProof

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Signatures == nil {
		aux.Signatures = make(map[string]string)
	}

	*alfp = AggregatedLeaderFinalizationProof(aux)

	return nil

}

func (alfp AggregatedLeaderFinalizationProof) MarshalJSON() ([]byte, error) {

	type alias AggregatedLeaderFinalizationProof

	aux := alias(alfp)

	if aux.Signatures == nil {
		aux.Signatures = make(map[string]string)
	}

	return json.Marshal(aux)
}
