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

type QuorumRotationAttestation struct {
	EpochId       int               `json:"epochId"`
	NextEpochId   int               `json:"nextEpochId"`
	NextEpochHash string            `json:"nextEpochHash"`
	NextQuorum    []string          `json:"nextQuorum"`
	Proofs        map[string]string `json:"proofs"`
}

func (qra *QuorumRotationAttestation) UnmarshalJSON(data []byte) error {

	type alias QuorumRotationAttestation

	var aux alias

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	*qra = QuorumRotationAttestation(aux)

	return nil
}

func (qra QuorumRotationAttestation) MarshalJSON() ([]byte, error) {

	type alias QuorumRotationAttestation

	aux := alias(qra)

	if aux.Proofs == nil {
		aux.Proofs = make(map[string]string)
	}

	return json.Marshal(aux)
}
