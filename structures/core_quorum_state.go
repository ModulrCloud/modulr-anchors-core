package structures

import "encoding/json"

type CoreQuorumState struct {
	CurrentEpochId int      `json:"currentEpochId"`
	CurrentQuorum  []string `json:"currentQuorum"`
}

type QuorumRotationAttestation struct {
	EpochId     int               `json:"epochId"`
	NextEpochId int               `json:"nextEpochId"`
	NextQuorum  []string          `json:"nextQuorum"`
	Proofs      map[string]string `json:"proofs"`
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
