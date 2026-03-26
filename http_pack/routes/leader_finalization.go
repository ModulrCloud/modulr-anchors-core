package routes

import (
	"encoding/json"
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

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
	payload, _ := json.Marshal(structures.AcceptProofResponse{Accepted: accepted})
	ctx.Write(payload)
}

func storeAggregatedLeaderFinalizationFromRequest(proof structures.AggregatedLeaderFinalizationProof) error {

	if len(proof.Signatures) == 0 {
		return fmt.Errorf("missing signatures")
	}

	if utils.GetEpochHandlerByID(proof.EpochIndex) == nil {
		return fmt.Errorf("epoch %d is not in supported window", proof.EpochIndex)
	}

	coreState := utils.LoadCoreQuorumState()

	if coreState == nil {
		return fmt.Errorf("core quorum state not initialized")
	}

	if !utils.VerifyCoreAlfp(&proof, coreState) {
		return fmt.Errorf("ALFP cryptographic verification failed")
	}

	globals.MEMPOOL.AddAggregatedLeaderFinalizationProof(proof)
	return nil
}
