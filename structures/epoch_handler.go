package structures

type EpochDataHandler struct {
	Id                 int      `json:"id"`
	Hash               string   `json:"hash"`
	AnchorsRegistry    []string `json:"anchorsRegistry"`
	Quorum             []string `json:"quorum"`
	LeadersSequence    []string `json:"leadersSequence"`
	StartTimestamp     uint64   `json:"startTimestamp"`
	CurrentLeaderIndex int      `json:"currentLeaderIndex"`
}
