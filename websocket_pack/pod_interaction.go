package websocket_pack

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/gorilla/websocket"
)

const (
	MAX_RETRIES             = 3
	RETRY_INTERVAL          = 200 * time.Millisecond
	POD_READ_WRITE_DEADLINE = 2 * time.Second // timeout for read/write operations for POD (point of distribution)
)

var (
	POD_MUTEX       sync.Mutex      // Guards open/close & replace of PoD conn
	POD_WRITE_MUTEX sync.Mutex      // Single writer guarantee for PoD
	POD_CONNECTION  *websocket.Conn // Connection with PoD itself
)

func SendWebsocketMessageToPoD(msg []byte) ([]byte, error) {
	for attempt := 1; attempt <= MAX_RETRIES; attempt++ {
		POD_MUTEX.Lock()
		if POD_CONNECTION == nil {
			conn, err := openWebsocketConnectionWithPoD()
			if err != nil {
				POD_MUTEX.Unlock()
				time.Sleep(RETRY_INTERVAL)
				continue
			}
			POD_CONNECTION = conn
		}
		c := POD_CONNECTION
		POD_MUTEX.Unlock()

		POD_WRITE_MUTEX.Lock()
		_ = c.SetWriteDeadline(time.Now().Add(POD_READ_WRITE_DEADLINE))
		err := c.WriteMessage(websocket.TextMessage, msg)
		POD_WRITE_MUTEX.Unlock()
		if err != nil {
			POD_MUTEX.Lock()
			_ = c.Close()
			POD_CONNECTION = nil
			POD_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(POD_READ_WRITE_DEADLINE))
		_, resp, err := c.ReadMessage()
		if err != nil {
			POD_MUTEX.Lock()
			_ = c.Close()
			POD_CONNECTION = nil
			POD_MUTEX.Unlock()
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
		_, _ = SendWebsocketMessageToPoD(reqBytes)
	}
}

func openWebsocketConnectionWithPoD() (*websocket.Conn, error) {
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
