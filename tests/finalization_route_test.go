package tests

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	_ "github.com/modulrcloud/modulr-anchors-core/tests/testenv"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/gorilla/websocket"
	"github.com/lxzan/gws"
)

func TestAnchorGetFinalizationProofDoesNotSignConflictingBlocksConcurrently(t *testing.T) {
	validator := configureAnchorFinalizationRouteState(t)
	creator := cryptography.GenerateKeyPair("", "", nil)
	epochHandler := structures.EpochDataHandler{
		Id:              3,
		Hash:            "anchor-finalization-epoch",
		AnchorsRegistry: []string{creator.Pub},
		Quorum:          []string{validator.Pub},
		StartTimestamp:  uint64(time.Now().UnixMilli()),
	}
	setActiveAnchorFinalizationEpochForTest(epochHandler)

	epochFullID := epochHandler.Hash + "#" + strconv.Itoa(epochHandler.Id)
	blockA := buildSignedAnchorFinalizationBlockForTest(t, creator, epochFullID, 0, "conflict-a")
	blockB := buildSignedAnchorFinalizationBlockForTest(t, creator, epochFullID, 0, "conflict-b")
	if blockA.GetHash() == blockB.GetHash() {
		t.Fatalf("test setup produced identical block hashes")
	}

	serverURL := startAnchorFinalizationWebsocketServer(t)
	requests := []websocket_pack.WsFinalizationProofRequest{
		{
			Route: "get_finalization_proof",
			Block: blockA,
		},
		{
			Route: "get_finalization_proof",
			Block: blockB,
		},
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	responses := make([]map[string]any, len(requests))
	errs := make([]error, len(requests))
	for i := range requests {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			responses[idx], errs[idx] = requestAnchorFinalizationProofFromServer(serverURL, requests[idx])
		}(i)
	}
	close(start)
	wg.Wait()

	signedHashes := make(map[string]bool)
	for idx, resp := range responses {
		if errs[idx] != nil {
			if isExpectedNoResponse(errs[idx]) {
				continue
			}
			t.Fatalf("finalization proof request failed: %v", errs[idx])
		}
		if sig, _ := resp["finalizationProof"].(string); sig == "" {
			continue
		}
		votedForHash, _ := resp["votedForHash"].(string)
		if votedForHash == "" {
			t.Fatalf("signed response is missing votedForHash: %+v", resp)
		}
		signedHashes[votedForHash] = true
	}

	if len(signedHashes) == 0 {
		t.Fatalf("expected one block to receive a finalization signature, got responses %+v errors=%+v", responses, errs)
	}
	if len(signedHashes) > 1 {
		t.Fatalf("validator signed conflicting hashes for the same block id: %+v responses=%+v", signedHashes, responses)
	}
}

func configureAnchorFinalizationRouteState(t *testing.T) cryptography.Ed25519Box {
	t.Helper()

	keyPair := cryptography.GenerateKeyPair("", "", nil)
	globals.CONFIGURATION.PublicKey = keyPair.Pub
	globals.CONFIGURATION.PrivateKey = keyPair.Prv
	globals.GENESIS.NetworkId = "anchors-finalization-testnet"
	globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)
	databases.FINALIZATION_VOTING_STATS = openTempDB(t, "finalization-voting-stats")
	databases.EPOCH_DATA = openTempDB(t, "epoch-data")
	databases.BLOCKS = openTempDB(t, "blocks")
	databases.APPROVEMENT_THREAD_METADATA = openTempDB(t, "approvement-thread-metadata")

	t.Cleanup(func() {
		globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Store(true)
		globals.BLOCK_CREATORS_MUTEX_REGISTRY.DeleteEpoch(3)
	})

	return keyPair
}

func setActiveAnchorFinalizationEpochForTest(epochHandler structures.EpochDataHandler) {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()
	defer handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

	handlers.APPROVEMENT_THREAD_METADATA.Handler = structures.ApprovementThreadMetadataHandler{
		EpochDataHandler: epochHandler,
	}
}

func startAnchorFinalizationWebsocketServer(t *testing.T) string {
	t.Helper()

	upgrader := gws.NewUpgrader(&websocket_pack.Handler{}, &gws.ServerOption{
		ParallelEnabled: true,
		Recovery:        gws.Recovery,
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r)
		if err != nil {
			t.Errorf("failed to upgrade websocket request: %v", err)
			return
		}
		go conn.ReadLoop()
	}))
	t.Cleanup(server.Close)

	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func requestAnchorFinalizationProofFromServer(serverURL string, request websocket_pack.WsFinalizationProofRequest) (map[string]any, error) {
	conn, _, err := websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dial websocket test server: %w", err)
	}
	defer conn.Close()

	if err := conn.WriteJSON(request); err != nil {
		return nil, fmt.Errorf("write websocket request: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}
	_, raw, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read websocket response: %w", err)
	}

	var resp map[string]any
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode websocket response %q: %w", raw, err)
	}
	return resp, nil
}

func isExpectedNoResponse(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func buildSignedAnchorFinalizationBlockForTest(t *testing.T, creator cryptography.Ed25519Box, epochFullID string, index int, variant string) block_pack.Block {
	t.Helper()

	block := block_pack.Block{
		Creator: creator.Pub,
		Time:    int64(1000 + index),
		Epoch:   epochFullID,
		ExtraData: block_pack.ExtraDataToBlock{
			Rest: map[string]string{"variant": variant},
		},
		Index:    index,
		PrevHash: constants.ZeroHash,
	}
	block.Sig = cryptography.GenerateSignature(creator.Prv, block.GetHash())
	if !block.VerifySignature() {
		t.Fatalf("test block signature does not verify")
	}

	return block
}
