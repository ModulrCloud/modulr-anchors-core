package routes

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

func AcceptAggregatedAnchorRotationProofs(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req structures.AcceptAggregatedAnchorRotationProofRequest

	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"invalid payload"}`))
		return
	}

	if len(req.AggregatedRotationProofs) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"missing rotation proofs"}`))
		return
	}

	accepted := 0

	for _, proof := range req.AggregatedRotationProofs {
		if err := storeAggregatedRotationProofFromRequest(proof); err != nil {
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

func storeAggregatedRotationProofFromRequest(proof structures.AggregatedAnchorRotationProof) error {

	epochHandler := utils.GetEpochHandlerByID(proof.EpochIndex)

	if epochHandler == nil {
		return fmt.Errorf("epoch %d is not tracked", proof.EpochIndex)
	}

	if !slices.Contains(epochHandler.AnchorsRegistry, proof.Anchor) {
		return fmt.Errorf("creator %s is not part of epoch %d", proof.Anchor, proof.EpochIndex)
	}

	majority := utils.GetQuorumMajority(epochHandler)

	if len(proof.Signatures) < majority {
		return fmt.Errorf("insufficient signatures: %d < %d", len(proof.Signatures), majority)
	}

	if err := utils.VerifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
		return err
	}

	if existing, err := utils.LoadAggregatedAnchorRotationProof(proof.EpochIndex, proof.Anchor); err == nil {
		if existing.VotingStat.Index >= proof.VotingStat.Index {
			globals.MEMPOOL.AddAggregatedAnchorRotationProof(existing)
			return nil
		}
	}

	if err := utils.StoreAggregatedAnchorRotationProof(proof); err != nil {
		return fmt.Errorf("store rotation proof: %w", err)
	}

	globals.MEMPOOL.AddAggregatedAnchorRotationProof(proof)

	return nil
}
