package http_pack

import (
	"encoding/json"
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

	creatorMutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(proof.EpochIndex, proof.Anchor)

	creatorMutex.Lock()

	defer creatorMutex.Unlock()

	if err := verifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
		return err
	}

	if err := utils.StoreVotingStat(proof.EpochIndex, proof.Anchor, proof.VotingStat); err != nil {
		return fmt.Errorf("store voting stat: %w", err)
	}

	if existing, err := utils.LoadAggregatedAnchorRotationProof(proof.EpochIndex, proof.Anchor); err == nil {
		if existing.VotingStat.Index >= proof.VotingStat.Index && existing.VotingStat.Hash == proof.VotingStat.Hash {
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

func verifyAggregatedAnchorRotationProof(proof *structures.AggregatedAnchorRotationProof, epochHandler *structures.EpochDataHandler) error {
	if proof.VotingStat.Index < 0 || proof.VotingStat.Hash == "" {
		return fmt.Errorf("invalid voting stat")
	}
	if proof.VotingStat.Afp.BlockId == "" {
		return fmt.Errorf("missing AFP blockId")
	}
	expectedBlockId := fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
	if !strings.EqualFold(proof.VotingStat.Afp.BlockId, expectedBlockId) {
		return fmt.Errorf("AFP blockId mismatch")
	}
	if !strings.EqualFold(proof.VotingStat.Hash, proof.VotingStat.Afp.BlockHash) {
		return fmt.Errorf("AFP block hash mismatch")
	}
	blockParts := strings.Split(proof.VotingStat.Afp.BlockId, ":")
	if len(blockParts) != 3 {
		return fmt.Errorf("invalid AFP blockId format")
	}
	afpIndex, err := strconv.Atoi(blockParts[2])
	if err != nil || afpIndex != proof.VotingStat.Index {
		return fmt.Errorf("AFP index mismatch")
	}

	epochFullID := epochHandler.Hash + "#" + strconv.Itoa(epochHandler.Id)
	dataToVerify := strings.Join([]string{
		proof.VotingStat.Afp.PrevBlockHash,
		proof.VotingStat.Afp.BlockId,
		proof.VotingStat.Afp.BlockHash,
		epochFullID,
	}, ":")

	quorum := epochHandler.Quorum
	verified := 0
	seen := make(map[string]struct{})
	for voter, signature := range proof.Signatures {
		if signature == "" {
			continue
		}
		if _, dup := seen[voter]; dup {
			continue
		}
		if !slices.Contains(quorum, voter) {
			continue
		}
		if !cryptography.VerifySignature(dataToVerify, voter, signature) {
			continue
		}
		seen[voter] = struct{}{}
		verified++
	}

	majority := utils.GetQuorumMajority(epochHandler)
	if verified < majority {
		return fmt.Errorf("verified signatures %d < %d", verified, majority)
	}
	return nil
}
