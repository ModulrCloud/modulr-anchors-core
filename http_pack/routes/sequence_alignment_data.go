package routes

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/valyala/fasthttp"
)

func GetSequenceAlignmentData(ctx *fasthttp.RequestCtx) {

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsGet() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	anchorIndexRaw := string(ctx.QueryArgs().Peek("anchorIndex"))
	if anchorIndexRaw == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"missing anchorIndex"}`))
		return
	}

	anchorIndex, err := strconv.Atoi(anchorIndexRaw)
	if err != nil || anchorIndex < 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"invalid anchorIndex"}`))
		return
	}

	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	epochHandler := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler()
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	anchors := epochHandler.AnchorsRegistry
	if anchorIndex >= len(anchors)-1 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.Write([]byte(`{"err":"anchorIndex out of range"}`))
		return
	}

	anchorIndexLookup := make(map[string]int)
	for idx, anchor := range anchors {
		anchorIndexLookup[anchor] = idx
	}

	requiredAnchors := []string{anchors[anchorIndex]}
	var (
		foundAnchorIndex = -1
		foundCreator     string
		foundBlocks      = make(map[int]structures.SequenceAlignmentAnchorData)
		maxFoundIndex    int
	)

	for i := anchorIndex + 1; i < len(anchors); i++ {
		creator := anchors[i]
		candidateData := make(map[int]structures.SequenceAlignmentAnchorData)
		currentMax := -1
		allFound := true

		for _, rotated := range requiredAnchors {
			blockID, err := utils.LoadAggregatedAnchorRotationProofPresence(epochHandler.Id, creator, rotated)
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				ctx.Write([]byte(fmt.Sprintf(`{"err":"failed to read AARP presence: %s"}`, err.Error())))
				return
			}
			if blockID == "" {
				allFound = false
				break
			}

			blockIndex, err := parseBlockIndex(blockID)
			if err != nil {
				allFound = false
				break
			}

			proof, err := utils.LoadAggregatedAnchorRotationProof(epochHandler.Id, rotated)
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusInternalServerError)
				ctx.Write([]byte(fmt.Sprintf(`{"err":"failed to load AARP: %s"}`, err.Error())))
				return
			}
			if proof.Anchor == "" {
				allFound = false
				break
			}

			rotatedIndex, ok := anchorIndexLookup[rotated]
			if !ok {
				allFound = false
				break
			}

			candidateData[rotatedIndex] = structures.SequenceAlignmentAnchorData{
				AARP:         proof,
				FoundInBlock: blockIndex,
			}

			if blockIndex > currentMax {
				currentMax = blockIndex
			}
		}

		if allFound {
			foundAnchorIndex = i
			foundCreator = creator
			foundBlocks = candidateData
			maxFoundIndex = currentMax
			break
		}

		requiredAnchors = append(requiredAnchors, creator)
	}

	if foundAnchorIndex == -1 {
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Write([]byte(`{"err":"alignment data not found"}`))
		return
	}

	response := structures.SequenceAlignmentDataResponse{
		FoundInAnchorIndex: foundAnchorIndex,
		Anchors:            foundBlocks,
	}

	if afp, err := loadAggregatedFinalizationProof(epochHandler.Id, foundCreator, maxFoundIndex+1); err == nil && afp != nil {
		response.Afp = afp
	}

	payload, _ := json.Marshal(response)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(payload)
}

func parseBlockIndex(blockID string) (int, error) {
	parts := strings.Split(blockID, ":")
	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid blockId format")
	}
	idx, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, fmt.Errorf("invalid block index")
	}
	return idx, nil
}

func loadAggregatedFinalizationProof(epoch int, creator string, blockIndex int) (*structures.AggregatedFinalizationProof, error) {

	blockID := fmt.Sprintf("%d:%s:%d", epoch, creator, blockIndex)
	raw, err := databases.EPOCH_DATA.Get([]byte("AFP:"+blockID), nil)
	if err != nil {
		if err == ldbErrors.ErrNotFound {
			return nil, nil
		}
		return nil, err
	}

	var afp structures.AggregatedFinalizationProof
	if err := json.Unmarshal(raw, &afp); err != nil {
		return nil, err
	}
	return &afp, nil
}
