package websocket_pack

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/gorilla/websocket"
)

const (
	MAX_RETRIES         = 3
	RETRY_INTERVAL      = 200 * time.Millisecond
	READ_WRITE_DEADLINE = 2 * time.Second // timeout for read/write operations for POD (point of distribution)
)

var (
	ANCHORS_POD_ACCESS_MUTEX     sync.Mutex      // Guards open/close & replace of PoD conn
	ANCHORS_POD_READ_WRITE_MUTEX sync.Mutex      // Serializes request/response (write+read) on a single PoD conn
	ANCHORS_POD_CONNECTION       *websocket.Conn // Connection with PoD itself
)

func SendWebsocketMessageToAnchorsPoD(msg []byte) ([]byte, error) {
	for attempt := 1; attempt <= MAX_RETRIES; attempt++ {
		ANCHORS_POD_ACCESS_MUTEX.Lock()
		if ANCHORS_POD_CONNECTION == nil {
			conn, err := openWebsocketConnectionWithAnchorsPoD()
			if err != nil {
				ANCHORS_POD_ACCESS_MUTEX.Unlock()
				time.Sleep(RETRY_INTERVAL)
				continue
			}
			ANCHORS_POD_CONNECTION = conn
		}
		c := ANCHORS_POD_CONNECTION
		ANCHORS_POD_ACCESS_MUTEX.Unlock()

		// A single PoD websocket connection is used as an RPC-style channel (request -> single response).
		// Serialize the entire write+read to avoid concurrent reads and response mixups.
		ANCHORS_POD_READ_WRITE_MUTEX.Lock()
		_ = c.SetWriteDeadline(time.Now().Add(READ_WRITE_DEADLINE))
		err := c.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			ANCHORS_POD_READ_WRITE_MUTEX.Unlock()
			ANCHORS_POD_ACCESS_MUTEX.Lock()
			_ = c.Close()
			ANCHORS_POD_CONNECTION = nil
			ANCHORS_POD_ACCESS_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(READ_WRITE_DEADLINE))
		_, resp, err := c.ReadMessage()
		ANCHORS_POD_READ_WRITE_MUTEX.Unlock()
		if err != nil {
			ANCHORS_POD_ACCESS_MUTEX.Lock()
			_ = c.Close()
			ANCHORS_POD_CONNECTION = nil
			ANCHORS_POD_ACCESS_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("failed to send message to pod after %d attempts", MAX_RETRIES)
}

func SendBlockAndAfpToAnchorsPoD(block block_pack.Block, afp *structures.AggregatedFinalizationProof) {
	if afp == nil {
		return
	}

	req := WsAnchorBlockWithAfpStoreRequest{Route: "accept_anchor_block_with_afp", Block: block, Afp: *afp}
	if reqBytes, err := json.Marshal(req); err == nil {
		id := "ANCHOR_BLOCK:" + block.Epoch + ":" + block.Creator + ":" + strconv.Itoa(block.Index)
		if globals.CONFIGURATION.DisablePoDOutbox {
			_, _ = SendWebsocketMessageToAnchorsPoD(reqBytes)
			return
		}
		_ = SendToAnchorsPoDWithOutbox(id, reqBytes)
	}
}

func openWebsocketConnectionWithAnchorsPoD() (*websocket.Conn, error) {
	u, err := url.Parse(globals.CONFIGURATION.PointOfDistributionWS)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("dial error: %w", err)
	}

	return conn, nil
}
