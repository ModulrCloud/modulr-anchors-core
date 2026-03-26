package routes

import (
	"encoding/json"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

type CoreQuorumStateResponse struct {
	CurrentEpochId int      `json:"currentEpochId"`
	CurrentQuorum  []string `json:"currentQuorum"`
	AnchorPubkey   string   `json:"anchorPubkey"`
	Signature      string   `json:"signature"`
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

	stateBytes, err := json.Marshal(state)

	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetContentType("application/json")
		ctx.Write([]byte(`{"err": "Failed to serialize state"}`))
		return
	}

	sig := cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, string(stateBytes))

	resp := CoreQuorumStateResponse{
		CurrentEpochId: state.CurrentEpochId,
		CurrentQuorum:  state.CurrentQuorum,
		AnchorPubkey:   globals.CONFIGURATION.PublicKey,
		Signature:      sig,
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
