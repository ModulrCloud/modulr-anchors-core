package threads

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/syndtr/goleveldb/leveldb"
)

func BlocksGenerationThread() {

	for {

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()

		blockTime := handlers.APPROVEMENT_THREAD_METADATA.Handler.NetworkParameters.BlockTime

		epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

		for idx := range epochHandlers {
			generateBlock(&epochHandlers[idx])
		}

		time.Sleep(time.Duration(blockTime) * time.Millisecond)
	}

}

func getGenerationMetadata(epochFullID string) *structures.GenerationThreadMetadataHandler {

	handlers.GENERATION_THREAD_METADATA.Lock()
	defer handlers.GENERATION_THREAD_METADATA.Unlock()

	if metadata, ok := handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID]; ok {
		return metadata
	}

	metadata := &structures.GenerationThreadMetadataHandler{
		EpochFullId: epochFullID,
		PrevHash:    constants.ZeroHash,
		NextIndex:   0,
	}

	handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID] = metadata

	return metadata
}

func removeGenerationMetadata(epochFullID string) {

	handlers.GENERATION_THREAD_METADATA.Lock()

	defer handlers.GENERATION_THREAD_METADATA.Unlock()

	delete(handlers.GENERATION_THREAD_METADATA.Handlers, epochFullID)

}

func generateBlock(epochHandlerRef *structures.EpochDataHandler) {

	if epochHandlerRef == nil {
		return
	}

	epochFullID := epochHandlerRef.Hash + "#" + strconv.Itoa(epochHandlerRef.Id)

	epochIndex := epochHandlerRef.Id

	runtime := ensureFinalizationRuntime(epochHandlerRef)

	runtime.Lock()

	alreadyApprovedIndex := runtime.Grabber.AcceptedIndex

	runtime.Unlock()

	metadata := getGenerationMetadata(epochFullID)

	handlers.GENERATION_THREAD_METADATA.Lock()

	if metadata.EpochFullId != epochFullID {

		metadata.EpochFullId = epochFullID
		metadata.PrevHash = constants.ZeroHash
		metadata.NextIndex = 0
		globals.MEMPOOL.ClearEpochProofs(epochIndex)

	}

	shouldGenerateBlocks := metadata.NextIndex <= alreadyApprovedIndex+1

	handlers.GENERATION_THREAD_METADATA.Unlock()

	if !shouldGenerateBlocks {
		return
	}

	restData := make(map[string]string, len(globals.CONFIGURATION.ExtraDataToBlock))

	for key, value := range globals.CONFIGURATION.ExtraDataToBlock {
		restData[key] = value
	}

	aggregatedRotationProofs := globals.MEMPOOL.DrainAggregatedAnchorRotationProofs(epochIndex)
	aggregatedLeaderProofs := globals.MEMPOOL.DrainAggregatedLeaderFinalizationProofs(epochIndex)

	extraData := block_pack.ExtraDataToBlock{
		Rest:                               restData,
		AggregatedAnchorRotationProofs:     aggregatedRotationProofs,
		AggregatedLeaderFinalizationProofs: aggregatedLeaderProofs,
	}

	blockDbAtomicBatch := new(leveldb.Batch)

	blockCandidate := block_pack.NewBlock(extraData, epochFullID, metadata)

	blockHash := blockCandidate.GetHash()

	blockCandidate.SignBlock()

	blockID := strconv.Itoa(epochIndex) + ":" + globals.CONFIGURATION.PublicKey + ":" + strconv.Itoa(blockCandidate.Index)

	aggregatedProofsLabel := fmt.Sprintf("New block generated %s (hash: %s...) | AARPs=%d, ALFPs=%d", blockID, blockHash[:8], len(aggregatedRotationProofs), len(aggregatedLeaderProofs))

	utils.LogWithTime(aggregatedProofsLabel, utils.CYAN_COLOR)

	blockBytes, serializeErr := json.Marshal(blockCandidate)

	if serializeErr != nil {
		// If we cannot serialize, the proofs we just drained would be lost forever
		// (mempool is in-memory). Restore them so the next iteration can retry.
		globals.MEMPOOL.RestoreAggregatedAnchorRotationProofs(epochIndex, aggregatedRotationProofs)
		globals.MEMPOOL.RestoreAggregatedLeaderFinalizationProofs(epochIndex, aggregatedLeaderProofs)
		utils.LogWithTime(
			fmt.Sprintf("Block serialization failed for %s: %v (restored %d AARPs and %d ALFPs to mempool)", epochFullID, serializeErr, len(aggregatedRotationProofs), len(aggregatedLeaderProofs)),
			utils.YELLOW_COLOR,
		)
		return
	}

	handlers.GENERATION_THREAD_METADATA.Lock()
	metadata.PrevHash = blockHash
	metadata.NextIndex++
	gtBytes, gtErr := json.Marshal(metadata)
	handlers.GENERATION_THREAD_METADATA.Unlock()

	if gtErr != nil {
		// Same restore reasoning as above; do not advance state.
		handlers.GENERATION_THREAD_METADATA.Lock()
		metadata.NextIndex--
		handlers.GENERATION_THREAD_METADATA.Unlock()
		globals.MEMPOOL.RestoreAggregatedAnchorRotationProofs(epochIndex, aggregatedRotationProofs)
		globals.MEMPOOL.RestoreAggregatedLeaderFinalizationProofs(epochIndex, aggregatedLeaderProofs)
		return
	}

	blockDbAtomicBatch.Put([]byte(blockID), blockBytes)
	blockDbAtomicBatch.Put([]byte(constants.DBKeyPrefixGenerationThread+epochFullID), gtBytes)

	if err := databases.BLOCKS.Write(blockDbAtomicBatch, nil); err != nil {
		// Restore so the proofs are not silently lost; do not advance NextIndex.
		handlers.GENERATION_THREAD_METADATA.Lock()
		metadata.NextIndex--
		handlers.GENERATION_THREAD_METADATA.Unlock()
		globals.MEMPOOL.RestoreAggregatedAnchorRotationProofs(epochIndex, aggregatedRotationProofs)
		globals.MEMPOOL.RestoreAggregatedLeaderFinalizationProofs(epochIndex, aggregatedLeaderProofs)
		panic("Can't store GT and block candidate: " + err.Error())
	}

	// Persist ALFP inclusion markers, grouped by epoch (ALFPs from different
	// core epochs may end up in the same anchor block).
	if len(aggregatedLeaderProofs) > 0 {
		markersByEpoch := make(map[int][]string, 1)
		for _, alfp := range aggregatedLeaderProofs {
			markersByEpoch[alfp.EpochIndex] = append(markersByEpoch[alfp.EpochIndex], alfp.Leader)
		}
		inclusionBatch := new(leveldb.Batch)
		for epochId, leaders := range markersByEpoch {
			utils.MarkAlfpIncludedBatch(inclusionBatch, epochId, leaders)
		}
		if err := databases.EPOCH_DATA.Write(inclusionBatch, nil); err != nil {
			// Inclusion markers are an optimization (avoid re-pulling already-included
			// proofs from PoD). Block persistence already succeeded, so do not panic.
			utils.LogWithTime(
				fmt.Sprintf("Failed to persist ALFP inclusion markers for block %s: %v", blockID, err),
				utils.YELLOW_COLOR,
			)
		}
	}
}
