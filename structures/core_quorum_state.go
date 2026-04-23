package structures

import "encoding/json"

type CoreEpochData struct {
	EpochId         int      `json:"epochId"`
	EpochHash       string   `json:"epochHash"`
	Quorum          []string `json:"quorum"`
	LeadersSequence []string `json:"leadersSequence"`
}

type CoreQuorumState struct {
	LatestEpochId int `json:"latestEpochId"`
}

type NextEpochData struct {
	NextEpochHash               string   `json:"nextEpochHash"`
	NextEpochValidatorsRegistry []string `json:"nextEpochValidatorsRegistry"`
	NextEpochQuorum             []string `json:"nextEpochQuorum"`
	NextEpochLeadersSequence    []string `json:"nextEpochLeadersSequence"`
	// NextEpochStartTimestamp mirrors modulr-core's NextEpochDataHandler field:
	// canonical scheduled start time (UTC ms) of the next core epoch. Used by
	// AlfpCollectionThread to compute per-leader end timestamps for proactive
	// ALFP collection without depending on static genesis offsets that drift
	// from real core progress.
	NextEpochStartTimestamp uint64              `json:"nextEpochStartTimestamp"`
	DelayedTransactions     []map[string]string `json:"delayedTransactions"`
}

type AggregatedEpochRotationProof struct {
	EpochId           int               `json:"epochId"`
	NextEpochId       int               `json:"nextEpochId"`
	EpochData         NextEpochData     `json:"epochData"`
	EpochDataHash     string            `json:"epochDataHash"`
	FinishedOnHeight  int64             `json:"finishedOnHeight"`
	FinishedOnBlockId string            `json:"finishedOnBlockId"`
	FinishedOnHash    string            `json:"finishedOnHash"`
	Proofs            map[string]string `json:"proofs"`
}

func (eda *AggregatedEpochRotationProof) UnmarshalJSON(data []byte) error {
	type alias AggregatedEpochRotationProof

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	*eda = AggregatedEpochRotationProof(aux)

	return nil
}
