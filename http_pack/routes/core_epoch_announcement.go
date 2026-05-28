package routes

import (
	"encoding/json"
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/valyala/fasthttp"
)

func AcceptCoreEpochAnnouncementProof(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req structures.AcceptEpochAnnouncementProofRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"invalid payload"}`))
		return
	}

	if !utils.ApplyCoreEpochAnnouncementProof(&req.Proof) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"epoch announcement proof verification failed"}`))
		return
	}

	utils.LogWithTime(
		fmt.Sprintf("Core quorum catch-up: applied early epoch announcement proof %d -> %d", req.Proof.EpochId, req.Proof.NextEpochId),
		utils.CYAN_COLOR,
	)

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write([]byte(`{"accepted":1}`))
}
