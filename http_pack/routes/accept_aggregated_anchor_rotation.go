package routes

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/databases"
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

	receipts := make([]structures.AarpInclusionReceipt, 0)
	for _, proof := range req.AggregatedRotationProofs {
		if r, ok := buildAarpInclusionReceiptIfAvailable(proof.EpochIndex, globals.CONFIGURATION.PublicKey, proof.Anchor); ok {
			receipts = append(receipts, r)
		}
	}

	payload, _ := json.Marshal(structures.AcceptAggregatedAnchorRotationProofResponse{Accepted: accepted, Receipts: receipts})

	ctx.Write(payload)

}

func buildAarpInclusionReceiptIfAvailable(epochIndex int, receiverAnchor string, rotatedAnchor string) (structures.AarpInclusionReceipt, bool) {
	if epochIndex < 0 || receiverAnchor == "" || rotatedAnchor == "" {
		return structures.AarpInclusionReceipt{}, false
	}

	blockId, err := utils.LoadAggregatedAnchorRotationProofPresence(epochIndex, receiverAnchor, rotatedAnchor)
	if err != nil || blockId == "" {
		return structures.AarpInclusionReceipt{}, false
	}

	epochHandler := utils.GetEpochHandlerByID(epochIndex)
	if epochHandler == nil {
		return structures.AarpInclusionReceipt{}, false
	}

	// Parse block index and compute nextBlockId (AFP for next block proves this block is approved).
	parts := strings.Split(blockId, ":")
	if len(parts) != 3 {
		return structures.AarpInclusionReceipt{}, false
	}
	idx, convErr := strconv.Atoi(parts[2])
	if convErr != nil || idx < 0 {
		return structures.AarpInclusionReceipt{}, false
	}
	nextBlockId := parts[0] + ":" + parts[1] + ":" + strconv.Itoa(idx+1)

	// Load the block itself and ensure it really contains a valid AARP targeting rotatedAnchor.
	blockBytes, bErr := databases.BLOCKS.Get([]byte(blockId), nil)
	if bErr != nil || len(blockBytes) == 0 {
		return structures.AarpInclusionReceipt{}, false
	}

	var block block_pack.Block
	if json.Unmarshal(blockBytes, &block) != nil {
		return structures.AarpInclusionReceipt{}, false
	}
	if block.Creator != receiverAnchor || !block.VerifySignature() {
		return structures.AarpInclusionReceipt{}, false
	}

	if !utils.HasValidAggregatedAnchorRotationProof(block.ExtraData.AggregatedAnchorRotationProofs, rotatedAnchor, epochHandler) {
		return structures.AarpInclusionReceipt{}, false
	}

	afpBytes, aErr := databases.EPOCH_DATA.Get([]byte("AFP:"+nextBlockId), nil)
	if aErr != nil || len(afpBytes) == 0 {
		// Included but not yet provably approved (we need AFP for next block).
		return structures.AarpInclusionReceipt{
			Status:         "PENDING",
			EpochIndex:     epochIndex,
			ReceiverAnchor: receiverAnchor,
			RotatedAnchor:  rotatedAnchor,
			BlockId:        blockId,
		}, true
	}

	var afp structures.AggregatedFinalizationProof
	if json.Unmarshal(afpBytes, &afp) != nil || !utils.VerifyAggregatedFinalizationProof(&afp, epochHandler) {
		return structures.AarpInclusionReceipt{}, false
	}

	blockRaw, _ := json.Marshal(block)
	return structures.AarpInclusionReceipt{
		Status:         "OK",
		EpochIndex:     epochIndex,
		ReceiverAnchor: receiverAnchor,
		RotatedAnchor:  rotatedAnchor,
		BlockId:        blockId,
		Block:          blockRaw,
		Afp:            afpBytes,
	}, true
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

	// Trigger #2: if we observed a valid AARP targeting this anchor, stop sending any proofs to it.
	// (This is used by the AARP delivery thread to avoid sending to anchors under rotation.)
	utils.MarkAnchorDisabledByAarp(proof.EpochIndex, proof.Anchor)

	globals.MEMPOOL.AddAggregatedAnchorRotationProof(proof)

	return nil
}
