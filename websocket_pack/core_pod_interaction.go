package websocket_pack

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/gorilla/websocket"
)

var (
	CORE_POD_ACCESS_MUTEX     sync.Mutex
	CORE_POD_READ_WRITE_MUTEX sync.Mutex
	CORE_POD_CONNECTION       *websocket.Conn
)

type corePodQuorumRotationGetRequest struct {
	Route   string `json:"route"`
	EpochId int    `json:"epochId"`
}

type corePodQuorumRotationGetResponse struct {
	Attestation *structures.QuorumRotationAttestation `json:"attestation"`
}

func sendWebsocketMessageToCorePod(msg []byte) ([]byte, error) {
	podUrl := globals.CONFIGURATION.CorePointOfDistributionWS
	if podUrl == "" {
		return nil, fmt.Errorf("CORE_POINT_OF_DISTRIBUTION not configured")
	}

	for attempt := 1; attempt <= MAX_RETRIES; attempt++ {
		CORE_POD_ACCESS_MUTEX.Lock()
		if CORE_POD_CONNECTION == nil {
			u, err := url.Parse(podUrl)
			if err != nil {
				CORE_POD_ACCESS_MUTEX.Unlock()
				return nil, fmt.Errorf("invalid core pod url: %w", err)
			}
			conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				utils.LogWithTimeThrottled(
					"anchors_core:core_pod_dial_error",
					2*time.Second,
					fmt.Sprintf("ANCHORS-CORE: can't connect to Core-PoD (attempt %d/%d): %v", attempt, MAX_RETRIES, err),
					utils.YELLOW_COLOR,
				)
				CORE_POD_ACCESS_MUTEX.Unlock()
				time.Sleep(RETRY_INTERVAL)
				continue
			}
			CORE_POD_CONNECTION = conn
		}
		c := CORE_POD_CONNECTION
		CORE_POD_ACCESS_MUTEX.Unlock()

		CORE_POD_READ_WRITE_MUTEX.Lock()
		_ = c.SetWriteDeadline(time.Now().Add(READ_WRITE_DEADLINE))
		err := c.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			CORE_POD_READ_WRITE_MUTEX.Unlock()
			CORE_POD_ACCESS_MUTEX.Lock()
			_ = c.Close()
			CORE_POD_CONNECTION = nil
			CORE_POD_ACCESS_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		_ = c.SetReadDeadline(time.Now().Add(READ_WRITE_DEADLINE))
		_, resp, err := c.ReadMessage()
		CORE_POD_READ_WRITE_MUTEX.Unlock()
		if err != nil {
			CORE_POD_ACCESS_MUTEX.Lock()
			_ = c.Close()
			CORE_POD_CONNECTION = nil
			CORE_POD_ACCESS_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("failed to send message to core pod after %d attempts", MAX_RETRIES)
}

func GetQuorumRotationFromCorePod(epochId int) *structures.QuorumRotationAttestation {
	req := corePodQuorumRotationGetRequest{
		Route:   "get_quorum_rotation_attestation_from_pod",
		EpochId: epochId,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil
	}

	respBytes, err := sendWebsocketMessageToCorePod(reqBytes)
	if err != nil {
		return nil
	}

	var resp corePodQuorumRotationGetResponse
	if json.Unmarshal(respBytes, &resp) != nil {
		return nil
	}

	return resp.Attestation
}
