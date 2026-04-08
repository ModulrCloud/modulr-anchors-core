package structures

import "encoding/json"

type CoreEpochData struct {
	EpochId   int      `json:"epochId"`
	EpochHash string   `json:"epochHash"`
	Quorum    []string `json:"quorum"`
}

type CoreQuorumState struct {
	LatestEpochId int `json:"latestEpochId"`
}

type NextEpochData struct {
	NextEpochHash               string              `json:"nextEpochHash"`
	NextEpochValidatorsRegistry []string            `json:"nextEpochValidatorsRegistry"`
	NextEpochQuorum             []string            `json:"nextEpochQuorum"`
	NextEpochLeadersSequence    []string            `json:"nextEpochLeadersSequence"`
	DelayedTransactions         []map[string]string `json:"delayedTransactions"`
}

type EpochDataAttestation struct {
	EpochId       int               `json:"epochId"`
	NextEpochId   int               `json:"nextEpochId"`
	EpochData     NextEpochData     `json:"epochData"`
	EpochDataHash string            `json:"epochDataHash"`
	Proofs        map[string]string `json:"proofs"`
}

func (eda *EpochDataAttestation) UnmarshalJSON(data []byte) error {
	type alias EpochDataAttestation

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	*eda = EpochDataAttestation(aux)

	return nil
}
