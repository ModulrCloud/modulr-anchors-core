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

// GetRecoveryCoreQuorum returns the AggregatedEpochRotationProof that introduced the
// requested modulr-core epoch, signed by this anchor's private key. Used by the
// recovery procedure to collect anchor responses and determine the modulr-core
// quorum for a given epoch.
//
// Path param: epoch (int) — the epoch for which to return core epoch data.
func GetRecoveryCoreQuorum(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if utils.LoadCoreQuorumState() == nil {
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

	writeSignedRotationProofResponse(ctx, epochId)
}

// GetRecoveryLatestCoreQuorum returns the latest AggregatedEpochRotationProof that
// this anchor has applied (i.e. for CoreQuorumState.LatestEpochId), signed by this
// anchor's private key. Used by the recovery procedure to auto-discover the last
// known core epoch without the caller having to guess the epoch id.
//
// Returns 404 when the anchor has not yet applied any core epoch rotation
// (e.g. modulr-core is still in the genesis epoch).
func GetRecoveryLatestCoreQuorum(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	state := utils.LoadCoreQuorumState()
	if state == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "Core quorum state not initialized"}`))
		return
	}

	if state.LatestEpochId <= 0 {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "No epoch rotation proof yet (still in genesis epoch)"}`))
		return
	}

	writeSignedRotationProofResponse(ctx, state.LatestEpochId)
}

func writeSignedRotationProofResponse(ctx *fasthttp.RequestCtx, epochId int) {
	proof := utils.LoadAggregatedEpochRotationProof(epochId)
	if proof == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err": "No epoch rotation proof found for this epoch"}`))
		return
	}

	// Resolve URLs for every NEXT-epoch quorum member that this anchor knows
	// about. Recovery clients use these URLs to query core validators directly
	// (e.g. /recovery/last_finalized_height). Pubkeys with no resolvable URL
	// are simply omitted; the client unions URLs across anchors and tries them
	// in order, so missing entries here are not fatal.
	endpointsMap := make(map[string]structures.RecoveryValidatorEndpoints)
	if proof.EpochData.NextEpochQuorum != nil {
		resolved := utils.ResolveCoreValidatorEndpoints(proof.EpochData.NextEpochQuorum)
		for pk, eps := range resolved {
			if eps.ValidatorUrl == "" && eps.WssValidatorUrl == "" {
				continue
			}
			endpointsMap[pk] = structures.RecoveryValidatorEndpoints{
				ValidatorUrl:    eps.ValidatorUrl,
				WssValidatorUrl: eps.WssValidatorUrl,
			}
		}
	}

	innerPayload := structures.RecoveryCoreQuorumPayload{
		Proof:              proof,
		ValidatorEndpoints: endpointsMap,
	}

	payloadBytes, err := json.Marshal(innerPayload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err": "Failed to marshal payload"}`))
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
