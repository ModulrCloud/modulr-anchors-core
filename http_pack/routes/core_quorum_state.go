package routes

import (
	"encoding/json"
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

// GetCoreQuorumState returns the latest core quorum state (epoch, hash, quorum).
// Used by external tooling for a quick overview.
func GetCoreQuorumState(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	state := utils.LoadCoreQuorumState()
	if state == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "Core quorum state not initialized"}`))
		return
	}

	epochData := utils.LoadCoreEpochData(state.LatestEpochId)
	if epochData == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "Core epoch data not found"}`))
		return
	}

	respBytes, err := json.Marshal(epochData)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err": "Failed to serialize epoch data"}`))
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(respBytes)
}

// GetRecoveryCoreQuorum returns the EpochDataAttestation that introduced the
// requested modulr-core epoch, signed by this anchor's private key. Used by the
// recovery procedure to collect anchor responses and determine the modulr-core
// quorum for a given epoch.
//
// Path param: epoch (int) — the epoch for which to return core epoch data.
func GetRecoveryCoreQuorum(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	state := utils.LoadCoreQuorumState()
	if state == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "Core quorum state not initialized"}`))
		return
	}

	epochRaw := ctx.UserValue("epoch")
	epochStr, ok := epochRaw.(string)
	if !ok || epochStr == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err": "Missing epoch parameter"}`))
		return
	}

	epochId, err := strconv.Atoi(epochStr)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err": "Invalid epoch parameter"}`))
		return
	}

	attestation := utils.LoadEpochDataAttestation(epochId)
	if attestation == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "No epoch data attestation found for this epoch"}`))
		return
	}

	payloadBytes, err := json.Marshal(attestation)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err": "Failed to marshal attestation"}`))
		return
	}

	sig := cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, string(payloadBytes))

	resp := structures.RecoverySignedResponse{
		PubKey:    globals.CONFIGURATION.PublicKey,
		Payload:   payloadBytes,
		Signature: sig,
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err": "Failed to marshal response"}`))
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(respBytes)
}
