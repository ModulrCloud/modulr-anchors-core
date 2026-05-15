package websocket_pack

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

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
	ANCHORS_HTTP_CLIENT          = &http.Client{Timeout: 2 * time.Second}
)

type aggregatedEpochRotationProofGetRequest struct {
	Route   string `json:"route"`
	EpochId int    `json:"epochId"`
}

type aggregatedEpochRotationProofGetResponse struct {
	Proof *structures.AggregatedEpochRotationProof `json:"proof"`
}

// aggregatedLeaderFinalizationProofGetRequest mirrors modulr-core's
// WsAggregatedLeaderFinalizationProofRequest. PoD answers both core and
// anchors-core nodes with the same payload shape.
type aggregatedLeaderFinalizationProofGetRequest struct {
	Route      string `json:"route"`
	EpochIndex int    `json:"epochIndex"`
	Leader     string `json:"leader"`
}

type aggregatedLeaderFinalizationProofGetResponse struct {
	Proof *structures.AggregatedLeaderFinalizationProof `json:"proof"`
}

func SendWebsocketMessageToAnchorsPoD(msg []byte) ([]byte, error) {
	for attempt := 1; attempt <= MAX_RETRIES; attempt++ {
		ANCHORS_POD_ACCESS_MUTEX.Lock()
		if ANCHORS_POD_CONNECTION == nil {
			conn, err := openWebsocketConnectionWithAnchorsPoD()
			if err != nil {
				utils.LogWithTimeThrottled(
					"anchors_core:pod_dial_error",
					2*time.Second,
					fmt.Sprintf("ANCHORS-CORE: can't connect to Anchors-PoD (attempt %d/%d): %v", attempt, MAX_RETRIES, err),
					utils.YELLOW_COLOR,
				)
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
			utils.LogWithTimeThrottled(
				"anchors_core:pod_write_error",
				2*time.Second,
				fmt.Sprintf("ANCHORS-CORE: Anchors-PoD write failed (attempt %d/%d): %v", attempt, MAX_RETRIES, err),
				utils.YELLOW_COLOR,
			)
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
			utils.LogWithTimeThrottled(
				"anchors_core:pod_read_error",
				2*time.Second,
				fmt.Sprintf("ANCHORS-CORE: Anchors-PoD read failed (attempt %d/%d): %v", attempt, MAX_RETRIES, err),
				utils.YELLOW_COLOR,
			)
			ANCHORS_POD_ACCESS_MUTEX.Lock()
			_ = c.Close()
			ANCHORS_POD_CONNECTION = nil
			ANCHORS_POD_ACCESS_MUTEX.Unlock()
			time.Sleep(RETRY_INTERVAL)
			continue
		}

		return resp, nil
	}

	utils.LogWithTimeThrottled(
		"anchors_core:pod_send_failed",
		2*time.Second,
		fmt.Sprintf("ANCHORS-CORE: failed to send message to Anchors-PoD after %d attempts", MAX_RETRIES),
		utils.RED_COLOR,
	)
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

// GetAggregatedLeaderFinalizationProofFromPoD asks the unified PoD for an ALFP
// belonging to (epochIndex, leader). Returns nil when PoD does not have it (yet)
// or when the response is malformed. The caller is responsible for cryptographic
// verification — this function does not validate the proof.
func GetAggregatedLeaderFinalizationProofFromPoD(epochIndex int, leader string) *structures.AggregatedLeaderFinalizationProof {
	req := aggregatedLeaderFinalizationProofGetRequest{
		Route:      constants.WsRouteGetAggregatedLeaderFinalizationProof,
		EpochIndex: epochIndex,
		Leader:     leader,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil
	}

	respBytes, err := SendWebsocketMessageToAnchorsPoD(reqBytes)
	if err != nil {
		return nil
	}

	var resp aggregatedLeaderFinalizationProofGetResponse
	if json.Unmarshal(respBytes, &resp) != nil {
		return nil
	}

	return resp.Proof
}

func GetAggregatedEpochRotationProofFromPoD(epochId int) *structures.AggregatedEpochRotationProof {
	req := aggregatedEpochRotationProofGetRequest{
		Route:   "get_aggregated_epoch_rotation_proof_from_pod",
		EpochId: epochId,
	}

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return nil
	}

	respBytes, err := SendWebsocketMessageToAnchorsPoD(reqBytes)
	if err != nil {
		return nil
	}

	var resp aggregatedEpochRotationProofGetResponse
	if json.Unmarshal(respBytes, &resp) != nil {
		return nil
	}

	return resp.Proof
}

func GetAggregatedEpochRotationProofFromAnchorsByHTTP(targetEpochId int) *structures.AggregatedEpochRotationProof {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	registry := append([]string(nil), handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler().AnchorsRegistry...)
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	for _, anchorPubkey := range registry {
		if anchorPubkey == globals.CONFIGURATION.PublicKey {
			continue
		}

		anchorStorage := utils.GetAnchorFromApprovementThreadState(anchorPubkey)
		if anchorStorage == nil || anchorStorage.AnchorUrl == "" {
			continue
		}

		proof := getAggregatedEpochRotationProofFromAnchorHTTP(anchorPubkey, anchorStorage.AnchorUrl, targetEpochId)
		if proof != nil {
			return proof
		}
	}

	return nil
}

func GetAggregatedEpochRotationProofFromAnchorsByHTTPUnverified(targetEpochId int) *structures.AggregatedEpochRotationProof {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	registry := append([]string(nil), handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler().AnchorsRegistry...)
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	for _, anchorPubkey := range registry {
		if anchorPubkey == globals.CONFIGURATION.PublicKey {
			continue
		}

		anchorStorage := utils.GetAnchorFromApprovementThreadState(anchorPubkey)
		if anchorStorage == nil || anchorStorage.AnchorUrl == "" {
			continue
		}

		proof := getAggregatedEpochRotationProofFromAnchorHTTPUnverified(anchorPubkey, anchorStorage.AnchorUrl, targetEpochId)
		if proof != nil {
			return proof
		}
	}

	return nil
}

func getAggregatedEpochRotationProofFromAnchorHTTP(anchorPubkey, anchorURL string, targetEpochId int) *structures.AggregatedEpochRotationProof {
	proof := getAggregatedEpochRotationProofFromAnchorHTTPUnverified(anchorPubkey, anchorURL, targetEpochId)
	if proof == nil {
		return nil
	}

	if !utils.VerifyAggregatedEpochRotationProof(proof) {
		return nil
	}

	return proof
}

func getAggregatedEpochRotationProofFromAnchorHTTPUnverified(anchorPubkey, anchorURL string, targetEpochId int) *structures.AggregatedEpochRotationProof {
	resp, err := ANCHORS_HTTP_CLIENT.Get(anchorURL + "/recovery/core_quorum/" + strconv.Itoa(targetEpochId))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var recoveryResp structures.RecoverySignedResponse
	if json.NewDecoder(resp.Body).Decode(&recoveryResp) != nil {
		return nil
	}

	if recoveryResp.PubKey != anchorPubkey || len(recoveryResp.Payload) == 0 || recoveryResp.Signature == "" {
		return nil
	}

	if !cryptography.VerifySignature(string(recoveryResp.Payload), recoveryResp.PubKey, recoveryResp.Signature) {
		return nil
	}

	var payload structures.RecoveryCoreQuorumPayload
	if json.Unmarshal(recoveryResp.Payload, &payload) != nil || payload.Proof == nil {
		return nil
	}

	proof := payload.Proof
	if proof.NextEpochId != targetEpochId {
		return nil
	}

	return proof
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
