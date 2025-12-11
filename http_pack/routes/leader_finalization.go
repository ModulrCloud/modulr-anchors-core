package routes

import (
	"encoding/json"
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/valyala/fasthttp"
)

func AcceptAggregatedLeaderFinalizationProof(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req structures.AcceptLeaderFinalizationProofRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"invalid payload"}`))
		return
	}

	if len(req.LeaderFinalizations) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"missing leader finalizations"}`))
		return
	}

	accepted := 0
	for _, proof := range req.LeaderFinalizations {
		if err := storeAggregatedLeaderFinalizationFromRequest(proof); err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.Write([]byte(fmt.Sprintf(`{"err":"%s"}`, err.Error())))
			return
		}
		accepted++
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	payload, _ := json.Marshal(structures.AcceptAnchorRotationProofResponse{Accepted: accepted})
	ctx.Write(payload)
}

func storeAggregatedLeaderFinalizationFromRequest(proof structures.AggregatedLeaderFinalizationProof) error {

	if len(proof.Signatures) == 0 {
		return fmt.Errorf("missing signatures")
	}

	globals.MEMPOOL.AddAggregatedLeaderFinalizationProof(proof)
	return nil
}
