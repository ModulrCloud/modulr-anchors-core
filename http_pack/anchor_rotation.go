package http_pack

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/valyala/fasthttp"
)

type anchorRotationProofRequest struct {
	EpochIndex int                   `json:"epochIndex"`
	Creator    string                `json:"creator"`
	Proposal   structures.VotingStat `json:"proposal"`
}

type anchorRotationProofResponse struct {
	Status     string                 `json:"status"`
	Message    string                 `json:"message,omitempty"`
	Signature  string                 `json:"signature,omitempty"`
	VotingStat *structures.VotingStat `json:"votingStat,omitempty"`
}

func AnchorRotationProof(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsPost() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	var req anchorRotationProofRequest
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

	epochHandler := getEpochHandler(req.EpochIndex)
	if epochHandler == nil {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err":"epoch not found"}`))
		return
	}

	if !isCreatorInEpoch(req.Creator, epochHandler.AnchorsRegistry) {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err":"creator not found"}`))
		return
	}

	creatorMutex := utils.GetBlockCreatorMutex(req.EpochIndex, req.Creator)
	creatorMutex.Lock()
	defer creatorMutex.Unlock()

	if !utils.IsFinalizationProofsDisabled(req.EpochIndex, req.Creator) {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"creator is still healthy"}`))
		return
	}

	currentStat, err := readVotingStat(req.EpochIndex, req.Creator)
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
		handleMatchingProposal(ctx, currentStat, proposal, epochHandler)
		return
	default:
		handleUpgradeProposal(ctx, currentStat, proposal, req.EpochIndex, req.Creator, epochHandler)
		return
	}
}

func getEpochHandler(id int) *structures.EpochDataHandler {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	defer handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()
	epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
	for idx := range epochHandlers {
		if epochHandlers[idx].Id == id {
			return &epochHandlers[idx]
		}
	}
	return nil
}

func isCreatorInEpoch(creator string, registry []string) bool {
	for _, candidate := range registry {
		if candidate == creator {
			return true
		}
	}
	return false
}

func respondWithUpgrade(ctx *fasthttp.RequestCtx, stat structures.VotingStat) {
	ctx.SetStatusCode(fasthttp.StatusConflict)
	payload, _ := json.Marshal(anchorRotationProofResponse{
		Status:     "UPGRADE",
		Message:    "network progressed further",
		VotingStat: &stat,
	})
	ctx.Write(payload)
}

func handleMatchingProposal(ctx *fasthttp.RequestCtx, current, proposal structures.VotingStat, epochHandler *structures.EpochDataHandler) {
	if current.Index < 0 || current.Hash == "" {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"no finalized blocks recorded"}`))
		return
	}

	if strings.ToLower(current.Hash) != strings.ToLower(proposal.Hash) {
		ctx.SetStatusCode(fasthttp.StatusConflict)
		ctx.Write([]byte(`{"err":"hash mismatch"}`))
		return
	}

	respondWithSignature(ctx, current, epochHandler)
}

func handleUpgradeProposal(ctx *fasthttp.RequestCtx, current, proposal structures.VotingStat, epochIndex int, creator string, epochHandler *structures.EpochDataHandler) {
	if err := validateUpgradeProposal(current, proposal, epochIndex, creator, epochHandler); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		payload, _ := json.Marshal(anchorRotationProofResponse{Status: "ERROR", Message: err.Error()})
		ctx.Write(payload)
		return
	}

	if err := storeVotingStat(epochIndex, creator, proposal); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err":"failed to persist voting stat"}`))
		return
	}

	respondWithSignature(ctx, proposal, epochHandler)
}

func respondWithSignature(ctx *fasthttp.RequestCtx, stat structures.VotingStat, epochHandler *structures.EpochDataHandler) {
	epochFullID := epochHandler.Hash + "#" + strconv.Itoa(epochHandler.Id)
	dataToSign := strings.Join([]string{stat.Afp.PrevBlockHash, stat.Afp.BlockId, stat.Afp.BlockHash, epochFullID}, ":")
	signature := cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, dataToSign)
	payload, _ := json.Marshal(anchorRotationProofResponse{
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

func readVotingStat(epochIndex int, creator string) (structures.VotingStat, error) {
	key := buildVotingStatKey(epochIndex, creator)
	stat := structures.NewVotingStatTemplate()
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(key, nil)
	if err != nil {
		if errors.Is(err, ldbErrors.ErrNotFound) {
			return stat, nil
		}
		return stat, err
	}
	if len(raw) == 0 {
		return stat, nil
	}
	if err := json.Unmarshal(raw, &stat); err != nil {
		return stat, err
	}
	return stat, nil
}

func storeVotingStat(epochIndex int, creator string, stat structures.VotingStat) error {
	payload, err := json.Marshal(stat)
	if err != nil {
		return err
	}
	return databases.FINALIZATION_VOTING_STATS.Put(buildVotingStatKey(epochIndex, creator), payload, nil)
}

func buildVotingStatKey(epochIndex int, creator string) []byte {
	return []byte(strconv.Itoa(epochIndex) + ":" + creator)
}
