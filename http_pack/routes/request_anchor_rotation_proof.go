package routes

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/valyala/fasthttp"
)

func RequestAnchorRotationProof(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req structures.AnchorRotationProofRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"invalid payload"}`))
		return
	}

	if req.EpochIndex < 0 || req.Creator == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"missing epochIndex or creator"}`))
		return
	}

	epochHandler := utils.GetEpochHandlerByID(req.EpochIndex)
	if epochHandler == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err":"epoch not found"}`))
		return
	}

	if !slices.Contains(epochHandler.AnchorsRegistry, req.Creator) {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err":"creator not found"}`))
		return
	}

	creatorMutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(req.EpochIndex, req.Creator)
	creatorMutex.Lock()
	defer creatorMutex.Unlock()

	if !utils.IsFinalizationProofsDisabled(req.EpochIndex, req.Creator) {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"creator is still healthy"}`))
		return
	}

	currentStat, err := utils.ReadVotingStat(req.EpochIndex, req.Creator)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err":"failed to read voting stats"}`))
		return
	}

	proposal := req.Proposal
	switch {
	case proposal.Index < currentStat.Index:
		respondWithUpgrade(ctx, currentStat)
		return
	case proposal.Index == currentStat.Index:
		handleMatchingProposal(ctx, req.Creator, currentStat, proposal, epochHandler)
		return
	default:
		handleUpgradeProposal(ctx, currentStat, proposal, req.EpochIndex, req.Creator, epochHandler)
		return
	}
}

func respondWithUpgrade(ctx *fasthttp.RequestCtx, stat structures.VotingStat) {
	ctx.SetStatusCode(fasthttp.StatusConflict)
	payload, _ := json.Marshal(structures.AnchorRotationProofResponse{
		Status:     "UPGRADE",
		Message:    "network progressed further",
		VotingStat: &stat,
	})
	ctx.Write(payload)
}

func handleMatchingProposal(ctx *fasthttp.RequestCtx, creator string, current, proposal structures.VotingStat, epochHandler *structures.EpochDataHandler) {
	if current.Index < 0 || current.Hash == "" {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"no finalized blocks recorded"}`))
		return
	}

	if !strings.EqualFold(current.Hash, proposal.Hash) {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"hash mismatch"}`))
		return
	}

	respondWithSignature(ctx, creator, current, epochHandler)
}

func handleUpgradeProposal(ctx *fasthttp.RequestCtx, current, proposal structures.VotingStat, epochIndex int, creator string, epochHandler *structures.EpochDataHandler) {
	if err := validateUpgradeProposal(current, proposal, epochIndex, creator, epochHandler); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		payload, _ := json.Marshal(structures.AnchorRotationProofResponse{Status: "ERROR", Message: err.Error()})
		ctx.Write(payload)
		return
	}

	if err := utils.StoreVotingStat(epochIndex, creator, proposal); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err":"failed to persist voting stat"}`))
		return
	}

	respondWithSignature(ctx, creator, proposal, epochHandler)
}

func respondWithSignature(ctx *fasthttp.RequestCtx, anchor string, stat structures.VotingStat, epochHandler *structures.EpochDataHandler) {
	anchorIndex := slices.Index(epochHandler.AnchorsRegistry, anchor)
	if anchorIndex < 0 {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err":"anchor not part of epoch"}`))
		return
	}
	dataToSign := utils.BuildAnchorRotationProofPayload(anchor, stat.Index, stat.Hash, epochHandler.Id)
	signature := cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, dataToSign)
	payload, _ := json.Marshal(structures.AnchorRotationProofResponse{
		Status:     "OK",
		Signature:  signature,
		VotingStat: &stat,
	})
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(payload)
}

func validateUpgradeProposal(current, proposal structures.VotingStat, epochIndex int, creator string, epochHandler *structures.EpochDataHandler) error {
	if proposal.Index <= current.Index {
		return fmt.Errorf("proposal index %d does not advance current index %d", proposal.Index, current.Index)
	}

	if proposal.Hash == "" || !strings.EqualFold(proposal.Hash, proposal.Afp.BlockHash) {
		return errors.New("proposal hash does not match AFP block hash")
	}

	blockParts := strings.Split(proposal.Afp.BlockId, ":")
	if len(blockParts) != 3 {
		return errors.New("invalid AFP blockId")
	}

	afpEpoch, err := strconv.Atoi(blockParts[0])
	if err != nil || afpEpoch != epochIndex {
		return errors.New("AFP epoch mismatch")
	}

	if blockParts[1] != creator {
		return errors.New("AFP creator mismatch")
	}

	afpIndex, err := strconv.Atoi(blockParts[2])
	if err != nil || afpIndex != proposal.Index {
		return errors.New("AFP index mismatch")
	}

	if proposal.Afp.PrevBlockHash == "" || !strings.EqualFold(proposal.Afp.PrevBlockHash, current.Hash) {
		return errors.New("AFP prev hash mismatch")
	}

	if !utils.VerifyAggregatedFinalizationProof(&proposal.Afp, epochHandler) {
		return errors.New("invalid aggregated finalization proof")
	}

	return nil
}
