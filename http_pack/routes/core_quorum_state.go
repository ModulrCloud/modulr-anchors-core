package routes

import (
	"encoding/json"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

type CoreQuorumStateResponse struct {
	LatestEpochId   int      `json:"latestEpochId"`
	LatestEpochHash string   `json:"latestEpochHash"`
	LatestQuorum    []string `json:"latestQuorum"`
	AnchorPubkey    string   `json:"anchorPubkey"`
	Signature       string   `json:"signature"`
}

func GetCoreQuorumState(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	state := utils.LoadCoreQuorumState()

	if state == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		ctx.Write([]byte(`{"err": "Core quorum state not initialized"}`))
		return
	}

	epochData := utils.LoadCoreEpochData(state.LatestEpochId)

	if epochData == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetContentType("application/json")
		ctx.Write([]byte(`{"err": "Core epoch data not found"}`))
		return
	}

	dataToSign, err := json.Marshal(epochData)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetContentType("application/json")
		ctx.Write([]byte(`{"err": "Failed to serialize epoch data"}`))
		return
	}

	sig := cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, string(dataToSign))

	resp := CoreQuorumStateResponse{
		LatestEpochId:   epochData.EpochId,
		LatestEpochHash: epochData.EpochHash,
		LatestQuorum:    epochData.Quorum,
		AnchorPubkey:    globals.CONFIGURATION.PublicKey,
		Signature:       sig,
	}

	respBytes, err := json.Marshal(resp)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetContentType("application/json")
		ctx.Write([]byte(`{"err": "Failed to serialize response"}`))
		return
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType("application/json")
	ctx.Write(respBytes)
}
