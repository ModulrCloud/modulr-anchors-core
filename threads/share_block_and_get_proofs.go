package threads

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/gorilla/websocket"
)

type ProofsGrabber struct {
	EpochId             int
	AcceptedIndex       int
	AcceptedHash        string
	AfpForPrevious      structures.AggregatedFinalizationProof
	HuntingForBlockId   string
	HuntingForBlockHash string
}

type finalizationRuntime struct {
	sync.Mutex
	Grabber      ProofsGrabber
	ProofsCache  map[string]string
	BlockToShare *block_pack.Block
	Connections  map[string]*websocket.Conn
	Waiter       *utils.QuorumWaiter
}

var finalizationRuntimes = struct {
	sync.RWMutex
	Data map[int]*finalizationRuntime
}{Data: make(map[int]*finalizationRuntime)}

func ensureFinalizationRuntime(epochHandler *structures.EpochDataHandler) *finalizationRuntime {
	finalizationRuntimes.RLock()
	if runtime, ok := finalizationRuntimes.Data[epochHandler.Id]; ok {
		finalizationRuntimes.RUnlock()
		return runtime
	}
	finalizationRuntimes.RUnlock()

	finalizationRuntimes.Lock()
	defer finalizationRuntimes.Unlock()
	if runtime, ok := finalizationRuntimes.Data[epochHandler.Id]; ok {
		return runtime
	}
	runtime := &finalizationRuntime{
		ProofsCache:  make(map[string]string),
		BlockToShare: &block_pack.Block{Index: -1},
		Connections:  make(map[string]*websocket.Conn),
	}
	grabber := ProofsGrabber{EpochId: epochHandler.Id, AcceptedIndex: -1, AcceptedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if rawGrabber, err := databases.FINALIZATION_VOTING_STATS.Get([]byte(strconv.Itoa(epochHandler.Id)+":PROOFS_GRABBER"), nil); err == nil {
		json.Unmarshal(rawGrabber, &grabber)
	}
	runtime.Grabber = grabber
	utils.OpenWebsocketConnectionsWithQuorum(epochHandler.Quorum, runtime.Connections)
	runtime.Waiter = utils.NewQuorumWaiter(len(epochHandler.Quorum))
	finalizationRuntimes.Data[epochHandler.Id] = runtime
	return runtime
}

func removeFinalizationRuntime(epochId int) {
	finalizationRuntimes.Lock()
	defer finalizationRuntimes.Unlock()
	if runtime, ok := finalizationRuntimes.Data[epochId]; ok {
		for _, conn := range runtime.Connections {
			conn.Close()
		}
		delete(finalizationRuntimes.Data, epochId)
	}
}

func ShareBlockAndGetProofsThread() {

	for {
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
		epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

		for idx := range epochHandlers {
			epochHandler := &epochHandlers[idx]
			runtime := ensureFinalizationRuntime(epochHandler)
			runFinalizationProofsGrabbing(epochHandler, runtime)
		}

		time.Sleep(200 * time.Millisecond)
	}

}

func runFinalizationProofsGrabbing(epochHandler *structures.EpochDataHandler, runtime *finalizationRuntime) {

	runtime.Lock()
	defer runtime.Unlock()
	epochFullId := epochHandler.Hash + "#" + strconv.Itoa(epochHandler.Id)
	blockIndexToHunt := strconv.Itoa(runtime.Grabber.AcceptedIndex + 1)
	blockIdForHunting := strconv.Itoa(epochHandler.Id) + ":" + globals.CONFIGURATION.PublicKey + ":" + blockIndexToHunt
	blockIdThatInPointer := strconv.Itoa(epochHandler.Id) + ":" + globals.CONFIGURATION.PublicKey + ":" + strconv.Itoa(runtime.BlockToShare.Index)
	majority := utils.GetQuorumMajority(epochHandler)
	if blockIdForHunting != blockIdThatInPointer {

		blockDataRaw, errDB := databases.BLOCKS.Get([]byte(blockIdForHunting), nil)
		if errDB == nil {

			if parseErr := json.Unmarshal(blockDataRaw, runtime.BlockToShare); parseErr != nil {

				return

			}

		} else {

			return

		}

	}

	blockHash := runtime.BlockToShare.GetHash()
	runtime.Grabber.HuntingForBlockId = blockIdForHunting
	runtime.Grabber.HuntingForBlockHash = blockHash
	if len(runtime.ProofsCache) < majority {

		message := websocket_pack.WsFinalizationProofRequest{

			Route: "get_finalization_proof",

			Block: *runtime.BlockToShare,

			PreviousBlockAfp: runtime.Grabber.AfpForPrevious,
		}

		if messageJsoned, err := json.Marshal(message); err == nil {

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			responses, ok := runtime.Waiter.SendAndWait(ctx, messageJsoned, epochHandler.Quorum, runtime.Connections, majority)

			if !ok {

				return

			}

			for _, raw := range responses {

				var parsedFinalizationProof websocket_pack.WsFinalizationProofResponse

				if err := json.Unmarshal(raw, &parsedFinalizationProof); err == nil {

					if parsedFinalizationProof.VotedForHash == runtime.Grabber.HuntingForBlockHash {

						dataThatShouldBeSigned := strings.Join(

							[]string{runtime.Grabber.AcceptedHash, runtime.Grabber.HuntingForBlockId, runtime.Grabber.HuntingForBlockHash, epochFullId}, ":",
						)

						finalizationProofIsOk := slices.Contains(epochHandler.Quorum, parsedFinalizationProof.Voter) && cryptography.VerifySignature(

							dataThatShouldBeSigned, parsedFinalizationProof.Voter, parsedFinalizationProof.FinalizationProof,
						)

						if finalizationProofIsOk {

							runtime.ProofsCache[parsedFinalizationProof.Voter] = parsedFinalizationProof.FinalizationProof

						}

					}

				}

			}

		}

		if len(runtime.ProofsCache) >= majority {

			aggregatedFinalizationProof := structures.AggregatedFinalizationProof{

				PrevBlockHash: runtime.Grabber.AcceptedHash,

				BlockId: blockIdForHunting,

				BlockHash: blockHash,

				Proofs: runtime.ProofsCache,
			}

			keyBytes := []byte("AFP:" + blockIdForHunting)

			valueBytes, _ := json.Marshal(aggregatedFinalizationProof)

			databases.EPOCH_DATA.Put(keyBytes, valueBytes, nil)

			proofGrabberKeyBytes := []byte(strconv.Itoa(epochHandler.Id) + ":PROOFS_GRABBER")

			proofGrabberValueBytes, marshalErr := json.Marshal(runtime.Grabber)

			if marshalErr == nil {

				proofsGrabberStoreErr := databases.FINALIZATION_VOTING_STATS.Put(proofGrabberKeyBytes, proofGrabberValueBytes, nil)

				if proofsGrabberStoreErr == nil {

					runtime.Grabber.AfpForPrevious = aggregatedFinalizationProof

					runtime.Grabber.AcceptedIndex++

					runtime.Grabber.AcceptedHash = runtime.Grabber.HuntingForBlockHash

					if runtime.Grabber.AcceptedIndex > 0 {

						msg := fmt.Sprintf(

							"%sApproved height for epoch %s%d %sis %s%d %s(hash:%s...) %s(%.3f%% agreements)",

							utils.RED_COLOR,

							utils.CYAN_COLOR,

							epochHandler.Id,

							utils.RED_COLOR,

							utils.CYAN_COLOR,

							runtime.Grabber.AcceptedIndex-1,

							utils.CYAN_COLOR,

							runtime.Grabber.AfpForPrevious.PrevBlockHash[:8],

							utils.GREEN_COLOR,

							float64(len(runtime.ProofsCache))/float64(len(epochHandler.Quorum))*100,
						)

						utils.LogWithTime(msg, utils.WHITE_COLOR)

					}

					runtime.ProofsCache = make(map[string]string)

				} else {

					return

				}

			} else {

				return

			}

		}

	}
}
