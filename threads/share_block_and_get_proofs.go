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

type FinalizationRuntime struct {
	sync.Mutex
	Grabber      ProofsGrabber
	ProofsCache  map[string]string
	BlockToShare *block_pack.Block
	Connections  map[string]*websocket.Conn
	ConnMu       sync.RWMutex
	Waiter       *utils.QuorumWaiter
}

var FINALIZATION_RUNTIMES = struct {
	sync.RWMutex
	Data map[int]*FinalizationRuntime
}{
	Data: make(map[int]*FinalizationRuntime),
}

func ShareBlockAndGetProofsThread() {

	for {
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
		epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

		progressed := false
		for idx := range epochHandlers {
			epochHandler := &epochHandlers[idx]
			runtime := ensureFinalizationRuntime(epochHandler)
			if runFinalizationProofsGrabbing(epochHandler, runtime) {
				progressed = true
			}
		}

		// If we didn't advance finalization for any epoch, back off to avoid a hot loop.
		// If we did advance, keep latency low but yield briefly to reduce lock/CPU pressure.
		if progressed {
			time.Sleep(5 * time.Millisecond)
		} else {
			time.Sleep(200 * time.Millisecond)
		}
	}

}

func runFinalizationProofsGrabbing(epochHandler *structures.EpochDataHandler, runtime *FinalizationRuntime) bool {
	epochIndexStr := strconv.Itoa(epochHandler.Id)
	majority := utils.GetQuorumMajority(epochHandler)

	// Snapshot minimal state under lock, then release it before doing I/O (DB/websocket).
	runtime.Lock()
	acceptedIndex := runtime.Grabber.AcceptedIndex
	acceptedHash := runtime.Grabber.AcceptedHash
	previousAfp := runtime.Grabber.AfpForPrevious
	currentBlockIndex := runtime.BlockToShare.Index
	// Copy current proofs cache (so we don't mutate the shared map while unlocked).
	localProofs := make(map[string]string, len(runtime.ProofsCache))
	for k, v := range runtime.ProofsCache {
		localProofs[k] = v
	}
	runtime.Unlock()

	blockIndexToHunt := strconv.Itoa(acceptedIndex + 1)
	blockIdForHunting := strconv.Itoa(epochHandler.Id) + ":" + globals.CONFIGURATION.PublicKey + ":" + blockIndexToHunt
	blockIdThatInPointer := strconv.Itoa(epochHandler.Id) + ":" + globals.CONFIGURATION.PublicKey + ":" + strconv.Itoa(currentBlockIndex)

	// Resolve the block we are hunting for (may require DB read).
	var blockToShare block_pack.Block
	if blockIdForHunting != blockIdThatInPointer {
		blockDataRaw, errDB := databases.BLOCKS.Get([]byte(blockIdForHunting), nil)
		if errDB != nil {
			return false
		}
		if parseErr := json.Unmarshal(blockDataRaw, &blockToShare); parseErr != nil {
			return false
		}
		// Update runtime pointer to the latest block-to-share (quick, under lock).
		runtime.Lock()
		*runtime.BlockToShare = blockToShare
		runtime.Unlock()
	} else {
		// Copy pointer value under lock.
		runtime.Lock()
		blockToShare = *runtime.BlockToShare
		runtime.Unlock()
	}

	blockHash := blockToShare.GetHash()

	// Record hunting markers (quick, under lock).
	runtime.Lock()
	runtime.Grabber.HuntingForBlockId = blockIdForHunting
	runtime.Grabber.HuntingForBlockHash = blockHash
	runtime.Unlock()

	// Only reach out to quorum if we still need more proofs.
	if len(localProofs) < majority {
		message := websocket_pack.WsFinalizationProofRequest{
			Route:            "get_finalization_proof",
			Block:            blockToShare,
			PreviousBlockAfp: previousAfp,
		}

		messageJsoned, err := json.Marshal(message)
		if err != nil {
			return false
		}

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		responses, ok := runtime.Waiter.SendAndWait(ctx, messageJsoned, epochHandler.Quorum, runtime.Connections, &runtime.ConnMu, majority)
		if !ok {
			return false
		}

		for _, raw := range responses {
			var parsedFinalizationProof websocket_pack.WsFinalizationProofResponse
			if err := json.Unmarshal(raw, &parsedFinalizationProof); err != nil {
				continue
			}
			if parsedFinalizationProof.VotedForHash != blockHash {
				continue
			}

			dataThatShouldBeSigned := strings.Join(
				[]string{acceptedHash, blockIdForHunting, blockHash, epochIndexStr}, ":",
			)

			finalizationProofIsOk := slices.Contains(epochHandler.Quorum, parsedFinalizationProof.Voter) &&
				cryptography.VerifySignature(dataThatShouldBeSigned, parsedFinalizationProof.Voter, parsedFinalizationProof.FinalizationProof)

			if finalizationProofIsOk {
				localProofs[parsedFinalizationProof.Voter] = parsedFinalizationProof.FinalizationProof
			}
		}

		// Commit latest proofs cache back to runtime (quick, under lock).
		runtime.Lock()
		runtime.ProofsCache = localProofs
		runtime.Unlock()
	}

	if len(localProofs) < majority {
		return false
	}

	aggregatedFinalizationProof := structures.AggregatedFinalizationProof{
		PrevBlockHash: acceptedHash,
		BlockId:       blockIdForHunting,
		BlockHash:     blockHash,
		Proofs:        localProofs,
	}

	// Persist AFP first (I/O without holding runtime lock).
	keyBytes := []byte("AFP:" + blockIdForHunting)
	valueBytes, _ := json.Marshal(aggregatedFinalizationProof)
	if err := databases.EPOCH_DATA.Put(keyBytes, valueBytes, nil); err != nil {
		return false
	}

	// Advance grabber state under lock, take a snapshot to persist, then release lock.
	runtime.Lock()
	runtime.Grabber.AfpForPrevious = aggregatedFinalizationProof
	runtime.Grabber.AcceptedIndex++
	runtime.Grabber.AcceptedHash = blockHash
	grabberSnapshot := runtime.Grabber
	runtime.ProofsCache = make(map[string]string)
	acceptedIdxForLog := runtime.Grabber.AcceptedIndex
	prevHashForLog := runtime.Grabber.AfpForPrevious.PrevBlockHash
	runtime.Unlock()

	// Persist grabber snapshot (I/O without holding runtime lock).
	proofGrabberKeyBytes := []byte(strconv.Itoa(epochHandler.Id) + ":PROOFS_GRABBER")
	proofGrabberValueBytes, marshalErr := json.Marshal(grabberSnapshot)
	if marshalErr != nil {
		return false
	}
	if err := databases.FINALIZATION_VOTING_STATS.Put(proofGrabberKeyBytes, proofGrabberValueBytes, nil); err != nil {
		return false
	}

	if acceptedIdxForLog > 0 {
		msg := fmt.Sprintf(
			"%sApproved height for epoch %s%d %sis %s%d %s(hash:%s...) %s(%.3f%% agreements)",
			utils.RED_COLOR,
			utils.CYAN_COLOR,
			epochHandler.Id,
			utils.RED_COLOR,
			utils.CYAN_COLOR,
			acceptedIdxForLog-1,
			utils.CYAN_COLOR,
			prevHashForLog[:8],
			utils.GREEN_COLOR,
			float64(len(localProofs))/float64(len(epochHandler.Quorum))*100,
		)
		utils.LogWithTime(msg, utils.WHITE_COLOR)
	}

	return true
}

func ensureFinalizationRuntime(epochHandler *structures.EpochDataHandler) *FinalizationRuntime {
	FINALIZATION_RUNTIMES.RLock()
	if runtime, ok := FINALIZATION_RUNTIMES.Data[epochHandler.Id]; ok {
		FINALIZATION_RUNTIMES.RUnlock()
		return runtime
	}
	FINALIZATION_RUNTIMES.RUnlock()

	FINALIZATION_RUNTIMES.Lock()
	defer FINALIZATION_RUNTIMES.Unlock()
	if runtime, ok := FINALIZATION_RUNTIMES.Data[epochHandler.Id]; ok {
		return runtime
	}
	runtime := &FinalizationRuntime{
		ProofsCache:  make(map[string]string),
		BlockToShare: &block_pack.Block{Index: -1},
		Connections:  make(map[string]*websocket.Conn),
	}
	grabber := ProofsGrabber{EpochId: epochHandler.Id, AcceptedIndex: -1, AcceptedHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	if rawGrabber, err := databases.FINALIZATION_VOTING_STATS.Get([]byte(strconv.Itoa(epochHandler.Id)+":PROOFS_GRABBER"), nil); err == nil {
		json.Unmarshal(rawGrabber, &grabber)
	}
	runtime.Grabber = grabber
	utils.OpenWebsocketConnectionsWithQuorum(epochHandler.Quorum, runtime.Connections, &runtime.ConnMu)
	runtime.Waiter = utils.NewQuorumWaiter(len(epochHandler.Quorum))
	FINALIZATION_RUNTIMES.Data[epochHandler.Id] = runtime
	return runtime
}

func removeFinalizationRuntime(epochId int) {
	FINALIZATION_RUNTIMES.Lock()
	defer FINALIZATION_RUNTIMES.Unlock()
	if runtime, ok := FINALIZATION_RUNTIMES.Data[epochId]; ok {
		for _, conn := range runtime.Connections {
			conn.Close()
		}
		delete(FINALIZATION_RUNTIMES.Data, epochId)
	}
}
