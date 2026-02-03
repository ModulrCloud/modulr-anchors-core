package threads

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/syndtr/goleveldb/leveldb"
)

func EpochRotationThread() {

	for {

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()

		handlerCopy := handlers.APPROVEMENT_THREAD_METADATA.Handler

		currentEpoch := handlerCopy.GetEpochHandler()

		networkParams := handlerCopy.GetNetworkParams()

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

		if currentEpoch.Hash == "" {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		if utils.EpochStillFresh(&currentEpoch, &networkParams) {
			time.Sleep(200 * time.Millisecond)
			continue
		}

		globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(false)

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()

		handlerRef := &handlers.APPROVEMENT_THREAD_METADATA.Handler

		latestIndex := len(handlerRef.SupportedEpochs) - 1

		if latestIndex < 0 {

			handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

			globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)

			time.Sleep(200 * time.Millisecond)

			continue

		}

		epochHandlerRef := handlerRef.SupportedEpochs[latestIndex]

		if utils.EpochStillFresh(&epochHandlerRef, &handlerRef.NetworkParameters) {

			handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

			globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)

			time.Sleep(200 * time.Millisecond)

			continue

		}

		atomicBatch := new(leveldb.Batch)

		nextEpochId := epochHandlerRef.Id + 1

		nextEpochHash := utils.Blake3(epochHandlerRef.Hash)

		nextEpochQuorumSize := handlerRef.NetworkParameters.QuorumSize

		nextEpochHandler := structures.EpochDataHandler{
			Id:              nextEpochId,
			Hash:            nextEpochHash,
			AnchorsRegistry: epochHandlerRef.AnchorsRegistry,
			Quorum:          utils.GetCurrentEpochQuorum(&epochHandlerRef, nextEpochQuorumSize, nextEpochHash),
			StartTimestamp:  epochHandlerRef.StartTimestamp + uint64(handlerRef.NetworkParameters.EpochDuration),
		}

		handlerRef.SupportedEpochs = append(handlerRef.SupportedEpochs, nextEpochHandler)

		if len(handlerRef.SupportedEpochs) > handlerRef.NetworkParameters.MaxEpochsToSupport {

			dropped := handlerRef.SupportedEpochs[0]

			handlerRef.SupportedEpochs = handlerRef.SupportedEpochs[1:]

			keyValue := []byte("EPOCH_FINISH:" + strconv.Itoa(dropped.Id))

			if err := databases.EPOCH_DATA.Put(keyValue, []byte("TRUE"), nil); err != nil {
				panic("Failed to mark epoch as finished: " + err.Error())
			}

			removeFinalizationRuntime(dropped.Id)

			epochFullID := dropped.Hash + "#" + strconv.Itoa(dropped.Id)

			removeGenerationMetadata(epochFullID)

			globals.MEMPOOL.RemoveEpochMempool(dropped.Id)
			globals.BLOCK_CREATORS_MUTEX_REGISTRY.DeleteEpoch(dropped.Id)
			DeleteHealthSnapshotsForEpoch(dropped.Id)
			DeleteHealthConnectionsForEpoch(dropped.Id)
			utils.ClearAggregatedAnchorRotationProofCache(dropped.Id)

			if err := databases.BLOCKS.Delete([]byte("GT:"+epochFullID), nil); err != nil {
				utils.LogWithTime("Failed to delete generation metadata: "+err.Error(), utils.RED_COLOR)
			}

		}

		handlerRef.SyncEpochPointers()

		jsonedHandler, _ := json.Marshal(handlerRef)

		atomicBatch.Put([]byte("AT"), jsonedHandler)

		if batchCommitErr := databases.APPROVEMENT_THREAD_METADATA.Write(atomicBatch, nil); batchCommitErr != nil {
			panic("Error with writing batch to approvement thread db. Try to launch again")
		}

		utils.LogWithTime("Epoch was updated => "+nextEpochHash+"#"+strconv.Itoa(nextEpochId), utils.GREEN_COLOR)

		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

		globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)

	}

}
