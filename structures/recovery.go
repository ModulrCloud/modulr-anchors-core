package structures

import "encoding/json"

type RecoverySignedResponse struct {
	PubKey    string          `json:"pubKey"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

// RecoveryValidatorEndpoints carries the URLs (HTTP + WSS) the anchor knows
// for a single core validator. Either field may be empty if the validator has
// not registered the corresponding URL.
type RecoveryValidatorEndpoints struct {
	ValidatorUrl    string `json:"validatorUrl"`
	WssValidatorUrl string `json:"wssValidatorUrl"`
}

// RecoveryCoreQuorumPayload is the inner JSON payload an anchor returns from
// /recovery/core_quorum/{epoch} and /recovery/latest_core_quorum. It carries
// the core-quorum-signed AggregatedEpochRotationProof together with the URLs
// the anchor knows for the next-epoch quorum members. The whole payload is
// covered by the outer anchor signature in RecoverySignedResponse.Signature.
type RecoveryCoreQuorumPayload struct {
	Proof                     *AggregatedEpochRotationProof         `json:"proof"`
	ValidatorEndpoints        map[string]RecoveryValidatorEndpoints `json:"validatorEndpoints"`
	RecoveryViewEpoch         int                                   `json:"recoveryViewEpoch"`
	RecoveryViewEpochDataHash string                                `json:"recoveryViewEpochDataHash"`
	RecoveryViewSource        string                                `json:"recoveryViewSource"`
	RecoveryViewFromEpoch     int                                   `json:"recoveryViewFromEpoch"`
	RecoveryViewVerifiedAtMs  int64                                 `json:"recoveryViewVerifiedAtMs"`
}
