package routes

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/valyala/fasthttp"
)

type CurrentAnchorAssumptionResponse struct {
	EpochIndex              int                                       `json:"epochIndex"`
	CurrentAnchorAssumption int                                       `json:"currentAnchorAssumption"`
	AnchorPubkey            string                                    `json:"anchorPubkey"`
	Proof                   *structures.SequenceAlignmentDataResponse `json:"proof,omitempty"`
}

func GetCurrentAnchorAssumption(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetContentType("application/json")

	if !ctx.IsGet() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.Write([]byte(`{"err":"method not allowed"}`))
		return
	}

	// epochIndex is optional; default to current epoch.
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	currentEpoch := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler().Id
	anchors := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler().AnchorsRegistry
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	epochIndex := currentEpoch
	if raw := ctx.QueryArgs().Peek("epochIndex"); len(raw) > 0 {
		if v, err := strconv.Atoi(string(raw)); err != nil || v < 0 {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.Write([]byte(`{"err":"invalid epochIndex"}`))
			return
		} else {
			epochIndex = v
		}
	}

	if len(anchors) == 0 {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Write([]byte(`{"err":"anchors registry is empty"}`))
		return
	}

	currentAssumption := 0
	var lastProof *structures.SequenceAlignmentDataResponse

	// Walk the rotation chain using the same logic as /sequence_alignment_data, but locally.
	for {
		if currentAssumption < 0 || currentAssumption >= len(anchors) {
			break
		}
		resp, err := computeSequenceAlignmentData(epochIndex, currentAssumption, anchors)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.Write([]byte(fmt.Sprintf(`{"err":"%s"}`, err.Error())))
			return
		}
		if resp == nil {
			break
		}
		// Safety: ensure progress and bounds.
		if resp.FoundInAnchorIndex <= currentAssumption || resp.FoundInAnchorIndex >= len(anchors) {
			break
		}
		lastProof = resp
		currentAssumption = resp.FoundInAnchorIndex
	}

	out := CurrentAnchorAssumptionResponse{
		EpochIndex:              epochIndex,
		CurrentAnchorAssumption: currentAssumption,
		AnchorPubkey:            anchors[currentAssumption],
		Proof:                   lastProof,
	}
	payload, _ := json.Marshal(out)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(payload)
}
