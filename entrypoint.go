package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/http_pack"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/threads"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/syndtr/goleveldb/leveldb"
)

func RunAnchorsChains() {

	if err := prepareAnchorsChains(); err != nil {

		utils.LogWithTime(fmt.Sprintf("Failed to prepare blockchain: %v", err), utils.RED_COLOR)

		utils.GracefulShutdown()

		return

	}

	//_________________________ RUN SEVERAL LOGICAL THREADS _________________________

	// ✅ 1.Thread to rotate epoch
	go threads.EpochRotationThread()

	// ✅ 2.Share our blocks within quorum members and get the finalization proofs
	go threads.ShareBlockAndGetProofsThread()

	// ✅ 3.Start to generate blocks
	go threads.BlocksGenerationThread()

	// ✅ 4.Start monitor anchors health
	go threads.HealthCheckerThread()

	// ✅ 5.Collect anchor rotation proofs from quorum
	go threads.AnchorRotationCollectorThread()

	//___________________ RUN SERVERS - WEBSOCKET AND HTTP __________________

	// Set the atomic flag to true

	globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)

	go websocket_pack.CreateWebsocketServer()

	http_pack.CreateHTTPServer()

}

func prepareAnchorsChains() error {

	if info, err := os.Stat(globals.CHAINDATA_PATH); err != nil {

		if os.IsNotExist(err) {

			if err := os.MkdirAll(globals.CHAINDATA_PATH, 0755); err != nil {

				return fmt.Errorf("create chaindata directory: %w", err)

			}

		} else {

			return fmt.Errorf("check chaindata directory: %w", err)

		}

	} else if !info.IsDir() {

		return fmt.Errorf("chaindata path %s exists and is not a directory", globals.CHAINDATA_PATH)

	}

	databases.BLOCKS = utils.OpenDb("BLOCKS")
	databases.EPOCH_DATA = utils.OpenDb("EPOCH_DATA")
	databases.APPROVEMENT_THREAD_METADATA = utils.OpenDb("APPROVEMENT_THREAD_METADATA")
	databases.FINALIZATION_VOTING_STATS = utils.OpenDb("FINALIZATION_VOTING_STATS")

	if data, err := databases.APPROVEMENT_THREAD_METADATA.Get([]byte("AT"), nil); err == nil {

		var atHandler structures.ApprovementThreadMetadataHandler

		if err := json.Unmarshal(data, &atHandler); err != nil {
			return fmt.Errorf("unmarshal APPROVEMENT_THREAD metadata: %w", err)
		}

		handlers.APPROVEMENT_THREAD_METADATA.Handler = atHandler

	} else {

		if err := loadGenesis(); err != nil {
			return fmt.Errorf("load genesis issue: %w", err)
		}

		serializedApprovementThread, err := json.Marshal(handlers.APPROVEMENT_THREAD_METADATA.Handler)

		if err != nil {
			return fmt.Errorf("marshal APPROVEMENT_THREAD metadata: %w", err)
		}

		if err := databases.APPROVEMENT_THREAD_METADATA.Put([]byte("AT"), serializedApprovementThread, nil); err != nil {
			return fmt.Errorf("save APPROVEMENT_THREAD metadata: %w", err)
		}

	}

	if err := ensureEpochWindow(&handlers.APPROVEMENT_THREAD_METADATA.Handler); err != nil {
		return fmt.Errorf("ensure epoch window: %w", err)
	}
	if err := loadGenerationThreadMetadata(); err != nil {
		return err
	}
	return nil
}

func loadGenesis() error {

	approvementThreadBatch := new(leveldb.Batch)

	epochTimestamp := globals.GENESIS.FirstEpochStartTimestamp

	anchorsRegistryForEpochHandler := []string{}

	// __________________________________ Load info about anchors __________________________________

	for _, anchorStorage := range globals.GENESIS.Anchors {

		anchorPubkey := anchorStorage.Pubkey

		serializedStorage, err := json.Marshal(anchorStorage)

		if err != nil {
			return err
		}

		approvementThreadBatch.Put([]byte(anchorPubkey+"_ANCHOR_STORAGE"), serializedStorage)

		anchorsRegistryForEpochHandler = append(anchorsRegistryForEpochHandler, anchorPubkey)

	}

	handlers.APPROVEMENT_THREAD_METADATA.Handler.NetworkParameters = globals.GENESIS.NetworkParameters.CopyNetworkParameters()

	// Commit changes

	if err := databases.APPROVEMENT_THREAD_METADATA.Write(approvementThreadBatch, nil); err != nil {
		return err
	}

	hashInput := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + globals.GENESIS.NetworkId + strconv.FormatUint(epochTimestamp, 10)

	initEpochHash := utils.Blake3(hashInput)

	epochHandlerForApprovementThread := structures.EpochDataHandler{
		Id:              0,
		Hash:            initEpochHash,
		AnchorsRegistry: anchorsRegistryForEpochHandler,
		StartTimestamp:  epochTimestamp,
		Quorum:          []string{}, // will be assigned
	}

	// Assign quorum - pseudorandomly and in deterministic way

	epochHandlerForApprovementThread.Quorum = utils.GetCurrentEpochQuorum(&epochHandlerForApprovementThread, handlers.APPROVEMENT_THREAD_METADATA.Handler.NetworkParameters.QuorumSize, initEpochHash)

	// Finally - assign a handler

	handlers.APPROVEMENT_THREAD_METADATA.Handler.EpochDataHandler = epochHandlerForApprovementThread
	handlers.APPROVEMENT_THREAD_METADATA.Handler.SupportedEpochs = []structures.EpochDataHandler{epochHandlerForApprovementThread}
	handlers.APPROVEMENT_THREAD_METADATA.Handler.SyncEpochPointers()

	// Store epoch data for API

	currentEpochDataHandler := handlers.APPROVEMENT_THREAD_METADATA.Handler.EpochDataHandler

	jsonedCurrentEpochDataHandler, err := json.Marshal(currentEpochDataHandler)

	if err != nil {
		return fmt.Errorf("marshal genesis epoch handler: %w", err)
	}

	if err := databases.EPOCH_DATA.Put([]byte("EPOCH_HANDLER:"+strconv.Itoa(currentEpochDataHandler.Id)), jsonedCurrentEpochDataHandler, nil); err != nil {
		return fmt.Errorf("store genesis epoch handler: %w", err)
	}

	return nil

}

func ensureEpochWindow(handler *structures.ApprovementThreadMetadataHandler) error {
	if handler.NetworkParameters.MaxEpochsToSupport <= 0 {
		handler.NetworkParameters.MaxEpochsToSupport = 1
	}
	if len(handler.SupportedEpochs) == 0 {
		handler.SupportedEpochs = []structures.EpochDataHandler{handler.EpochDataHandler}
	}
	if len(handler.SupportedEpochs) > handler.NetworkParameters.MaxEpochsToSupport {
		offset := len(handler.SupportedEpochs) - handler.NetworkParameters.MaxEpochsToSupport
		toDrop := handler.SupportedEpochs[:offset]
		handler.SupportedEpochs = handler.SupportedEpochs[offset:]
		for _, dropped := range toDrop {
			keyValue := []byte("EPOCH_FINISH:" + strconv.Itoa(dropped.Id))
			if err := databases.EPOCH_DATA.Put(keyValue, []byte("TRUE"), nil); err != nil {
				return fmt.Errorf("store finalization voting stats: %w", err)
			}
			epochFullID := dropped.Hash + "#" + strconv.Itoa(dropped.Id)
			if err := databases.BLOCKS.Delete([]byte("GT:"+epochFullID), nil); err != nil {
				return fmt.Errorf("delete blocks for epoch %s: %w", epochFullID, err)
			}
		}
	}
	handler.SyncEpochPointers()
	return nil
}

func loadGenerationThreadMetadata() error {
	epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
	legacyData, legacyErr := databases.BLOCKS.Get([]byte("GT"), nil)
	legacyUsed := false

	for _, epoch := range epochHandlers {
		epochFullID := epoch.Hash + "#" + strconv.Itoa(epoch.Id)
		key := []byte("GT:" + epochFullID)
		if data, err := databases.BLOCKS.Get(key, nil); err == nil {
			var gtHandler structures.GenerationThreadMetadataHandler
			if err := json.Unmarshal(data, &gtHandler); err != nil {
				return fmt.Errorf("unmarshal GENERATION_THREAD metadata: %w", err)
			}
			handlers.GENERATION_THREAD_METADATA.Lock()
			handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID] = &gtHandler
			handlers.GENERATION_THREAD_METADATA.Unlock()
			continue
		}
		if !legacyUsed && legacyErr == nil {
			var gtHandler structures.GenerationThreadMetadataHandler
			if err := json.Unmarshal(legacyData, &gtHandler); err == nil {
				gtHandler.EpochFullId = epochFullID
				handlers.GENERATION_THREAD_METADATA.Lock()
				handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID] = &gtHandler
				handlers.GENERATION_THREAD_METADATA.Unlock()
				legacyUsed = true
				continue
			}
		}
		handlers.GENERATION_THREAD_METADATA.Lock()
		if _, ok := handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID]; !ok {
			handlers.GENERATION_THREAD_METADATA.Handlers[epochFullID] = &structures.GenerationThreadMetadataHandler{
				EpochFullId: epochFullID,
				PrevHash:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				NextIndex:   0,
			}
		}
		handlers.GENERATION_THREAD_METADATA.Unlock()
	}

	return nil
}
