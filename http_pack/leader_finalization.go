package http_pack

import (
	"encoding/json"
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

func AcceptLeaderFinalizationData(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req structures.AcceptLeaderFinalizationDataRequest
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
		if err := storeLeaderFinalizationFromRequest(proof); err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.Write([]byte(fmt.Sprintf(`{"err":"%s"}`, err.Error())))
			return
		}
		accepted++
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	payload, _ := json.Marshal(structures.AcceptExtraDataResponse{Accepted: accepted})
	ctx.Write(payload)
}

func storeLeaderFinalizationFromRequest(proof structures.LeaderFinalizationProofBundle) error {
	if proof.ChainId == "" || proof.Leader == "" {
		return fmt.Errorf("missing chain or leader identifiers")
	}

	if proof.VotingStat.Index < 0 || proof.VotingStat.Hash == "" {
		return fmt.Errorf("invalid voting stat")
	}

	if len(proof.Signatures) == 0 {
		return fmt.Errorf("missing signatures")
	}

	if err := utils.StoreLeaderVotingStat(proof.ChainId, proof.Leader, proof.VotingStat); err != nil {
		return fmt.Errorf("store voting stat: %w", err)
	}

	if existing, err := utils.LoadLeaderFinalizationProof(proof.ChainId, proof.Leader); err == nil {
		if existing.VotingStat.Index >= proof.VotingStat.Index && existing.VotingStat.Hash == proof.VotingStat.Hash {
			handlers.AddLeaderFinalizationProofToMempool(existing)
			return nil
		}
	}

	if err := utils.StoreLeaderFinalizationProof(proof); err != nil {
		return fmt.Errorf("store leader finalization proof: %w", err)
	}

	handlers.AddLeaderFinalizationProofToMempool(proof)
	return nil
}
