package websocket_pack

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/syndtr/goleveldb/leveldb/util"
)

const POD_OUTBOX_PREFIX = "ANCHORS_POD_OUTBOX:"

const (
	anchorsPoDAsyncQueueSize = 2048
	anchorsPoDAsyncWorkers   = 2
)

var (
	anchorsPoDAsyncOnce  sync.Once
	anchorsPoDAsyncQueue chan outboxEntry
)

type PodStatusResponse struct {
	Status string `json:"status"`
}

func isPodAck(resp []byte) bool {
	var s PodStatusResponse
	if json.Unmarshal(resp, &s) != nil {
		return false
	}
	return strings.EqualFold(s.Status, "OK")
}

func podOutboxKey(id string) []byte {
	return []byte(POD_OUTBOX_PREFIX + id)
}

// SendToAnchorsPoDWithOutbox sends a message to Anchors PoD and requires an OK ack.
// On failure, it persists the message into FINALIZATION_VOTING_STATS for retry.
func SendToAnchorsPoDWithOutbox(id string, payload []byte) bool {
	if id == "" || len(payload) == 0 {
		return false
	}

	resp, err := SendWebsocketMessageToAnchorsPoD(payload)
	if err == nil && isPodAck(resp) {
		_ = databases.FINALIZATION_VOTING_STATS.Delete(podOutboxKey(id), nil)
		return true
	}

	_ = databases.FINALIZATION_VOTING_STATS.Put(podOutboxKey(id), payload, nil)
	return false
}

type outboxEntry struct {
	id      string
	payload []byte
	persist bool
}

func EnqueueAnchorsPoDStoreMessage(id string, payload []byte, persist bool) bool {
	if id == "" || len(payload) == 0 {
		return false
	}

	if persist && databases.FINALIZATION_VOTING_STATS != nil {
		_ = databases.FINALIZATION_VOTING_STATS.Put(podOutboxKey(id), payload, nil)
	}

	startAnchorsPoDAsyncWorkers()
	entry := outboxEntry{id: id, payload: append([]byte(nil), payload...), persist: persist}
	select {
	case anchorsPoDAsyncQueue <- entry:
		return true
	default:
		utils.LogWithTimeThrottled(
			"anchors_core:pod_async_queue_full",
			5*time.Second,
			"ANCHORS-CORE: async PoD store queue is full; store message remains in persistent outbox or is dropped when outbox is disabled",
			utils.YELLOW_COLOR,
		)
		return false
	}
}

func startAnchorsPoDAsyncWorkers() {
	anchorsPoDAsyncOnce.Do(func() {
		anchorsPoDAsyncQueue = make(chan outboxEntry, anchorsPoDAsyncQueueSize)
		for i := 0; i < anchorsPoDAsyncWorkers; i++ {
			go func() {
				for entry := range anchorsPoDAsyncQueue {
					sendAnchorsPoDOutboxEntry(entry)
				}
			}()
		}
	})
}

func sendAnchorsPoDOutboxEntry(entry outboxEntry) bool {
	resp, err := SendWebsocketMessageToAnchorsPoD(entry.payload)
	if err == nil && isPodAck(resp) {
		if entry.persist && databases.FINALIZATION_VOTING_STATS != nil {
			_ = databases.FINALIZATION_VOTING_STATS.Delete(podOutboxKey(entry.id), nil)
		}
		return true
	}

	if entry.persist && databases.FINALIZATION_VOTING_STATS != nil {
		_ = databases.FINALIZATION_VOTING_STATS.Put(podOutboxKey(entry.id), entry.payload, nil)
	}
	return false
}

func FlushAnchorsPoDOutboxOnce(limit int) int {
	if databases.FINALIZATION_VOTING_STATS == nil {
		return 0
	}
	if limit <= 0 {
		limit = 50
	}

	// Collect entries from LevelDB iterator first, then release it before doing network I/O.
	// Holding the iterator during slow websocket retries blocks LevelDB compaction.
	entries := make([]outboxEntry, 0, limit)

	it := databases.FINALIZATION_VOTING_STATS.NewIterator(util.BytesPrefix([]byte(POD_OUTBOX_PREFIX)), nil)
	for it.Next() {
		if len(entries) >= limit {
			break
		}
		key := string(it.Key())
		if !strings.HasPrefix(key, POD_OUTBOX_PREFIX) {
			continue
		}
		id := strings.TrimPrefix(key, POD_OUTBOX_PREFIX)
		payload := append([]byte(nil), it.Value()...)
		if len(payload) == 0 {
			_ = databases.FINALIZATION_VOTING_STATS.Delete([]byte(key), nil)
			continue
		}
		entries = append(entries, outboxEntry{id: id, payload: payload})
	}
	it.Release()

	sent := 0
	for _, entry := range entries {
		entry.persist = true
		if sendAnchorsPoDOutboxEntry(entry) {
			sent++
		}
	}
	return sent
}
