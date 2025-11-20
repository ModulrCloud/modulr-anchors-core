package threads

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/syndtr/goleveldb/leveldb"
)

const zeroPrevHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func getGenerationMetadata(epochFullID string) *structures.GenerationThreadMetadataHandler {
	handlers.GENERATION_THREAD_METADATA.Lock()
	defer handlers.GENERATION_THREAD_METADATA.Unlock()

	if metadata, ok := handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID]; ok {
		return metadata
	}

	metadata := &structures.GenerationThreadMetadataHandler{
		EpochFullId: epochFullID,
		PrevHash:    zeroPrevHash,
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

func generateBlock(epochHandlerRef *structures.EpochDataHandler) {
	if epochHandlerRef == nil {
		return
	}

	epochFullID := epochHandlerRef.Hash + "#" + strconv.Itoa(epochHandlerRef.Id)
	epochIndex := epochHandlerRef.Id

	runtime := ensureFinalizationRuntime(epochHandlerRef)
	runtime.Lock()
	acceptedIndex := runtime.Grabber.AcceptedIndex
	runtime.Unlock()

	metadata := getGenerationMetadata(epochFullID)

	handlers.GENERATION_THREAD_METADATA.Lock()
	if metadata.EpochFullId != epochFullID {
		metadata.EpochFullId = epochFullID
		metadata.PrevHash = zeroPrevHash
		metadata.NextIndex = 0
	}
	shouldGenerateBlocks := metadata.NextIndex <= acceptedIndex+1
	handlers.GENERATION_THREAD_METADATA.Unlock()

	if !shouldGenerateBlocks {
		return
	}

	fields := make(map[string]string, len(globals.CONFIGURATION.ExtraDataToBlock))
	for key, value := range globals.CONFIGURATION.ExtraDataToBlock {
		fields[key] = value
	}
	extraData := structures.BlockExtraData{
		Fields:                   fields,
		RotationProofs:           handlers.DrainRotationProofsFromMempool(),
		LeaderFinalizationProofs: handlers.DrainLeaderFinalizationProofsFromMempool(),
	}

	blockDbAtomicBatch := new(leveldb.Batch)

	blockCandidate := block_pack.NewBlock(extraData, epochFullID, metadata)
	blockHash := blockCandidate.GetHash()
	blockCandidate.SignBlock()

	blockID := strconv.Itoa(epochIndex) + ":" + globals.CONFIGURATION.PublicKey + ":" + strconv.Itoa(blockCandidate.Index)
	utils.LogWithTime("New block generated "+blockID+" (hash: "+blockHash[:8]+"...)", utils.CYAN_COLOR)

	blockBytes, serializeErr := json.Marshal(blockCandidate)
	if serializeErr != nil {
		return
	}

	handlers.GENERATION_THREAD_METADATA.Lock()
	metadata.PrevHash = blockHash
	metadata.NextIndex++
	handlers.GENERATION_THREAD_METADATA.Unlock()

	if gtBytes, err := json.Marshal(metadata); err == nil {
		blockDbAtomicBatch.Put([]byte(blockID), blockBytes)
		blockDbAtomicBatch.Put([]byte("GT:"+epochFullID), gtBytes)
		if err := databases.BLOCKS.Write(blockDbAtomicBatch, nil); err != nil {
			panic("Can't store GT and block candidate")
		}
	}
}
