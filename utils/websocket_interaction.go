package utils

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/gorilla/websocket"
)

type WebsocketGuards struct {
	ConnMu *sync.RWMutex
	// WriteMu keys are *websocket.Conn and values are *sync.Mutex.
	// This guarantees a single writer per actual websocket connection, regardless of id/pubkey mapping.
	//
	// IMPORTANT: We never delete entries synchronously to avoid the following race:
	//   1. Goroutine A loads mutex M for connection C via getWriteMuConn.
	//   2. Goroutine B (on error) deletes M from the map.
	//   3. Goroutine C calls getWriteMuConn(C) and LoadOrStores a brand-new M2.
	//   4. A locks M, C locks M2, both now write to the same conn C concurrently
	//      → gorilla/websocket panics.
	// All deletes go through ScheduleWriteMuCleanup which waits writeMuCleanupDelay
	// before actually removing the entry, giving any in-flight goroutine time to
	// finish its Write/Read round first.
	WriteMu *sync.Map
}

// writeMuCleanupDelay is how long we wait before removing a closed conn's
// WriteMu entry. Must exceed the longest possible in-flight request window
// on that conn (QuorumWaiter uses a 1s read deadline after the write, so
// ~3s is a comfortable safety margin).
const writeMuCleanupDelay = 3 * time.Second

func NewWebsocketGuards() *WebsocketGuards {
	return &WebsocketGuards{
		ConnMu:  &sync.RWMutex{},
		WriteMu: &sync.Map{},
	}
}

// ScheduleWriteMuCleanup removes the per-connection mutex entry from
// guards.WriteMu after writeMuCleanupDelay, giving any in-flight goroutine
// time to finish its Write/Read round before we drop the mutex. See the
// WriteMu field comment for why a direct Delete is unsafe.
//
// Nil-safe: no-ops when guards, WriteMu or conn is nil.
func ScheduleWriteMuCleanup(guards *WebsocketGuards, conn *websocket.Conn) {
	if guards == nil || guards.WriteMu == nil || conn == nil {
		return
	}
	go func(writeMu *sync.Map, c *websocket.Conn) {
		time.Sleep(writeMuCleanupDelay)
		writeMu.Delete(c)
	}(guards.WriteMu, conn)
}

type QuorumWaiter struct {
	responseCh chan QuorumResponse
	done       chan struct{}
	answered   map[string]struct{}
	responses  map[string][]byte
	timer      *time.Timer
	mu         sync.Mutex
	buf        []string
	failed     map[string]struct{}
	guards     *WebsocketGuards
}

type QuorumResponse struct {
	id  string
	msg []byte
}

// OpenWebsocketConnectionsWithUrlMap opens WS connections to a set of remote
// nodes addressed by `pubkey` using a caller-provided `pubkey -> wssUrl` map.
// Pubkeys with no URL in the map (or an empty URL) are skipped. Existing
// entries in `wsConnMap` are closed and replaced atomically under guards.
//
// This is the generic counterpart to OpenWebsocketConnectionsWithQuorum:
// the latter is hard-coded to anchor storage lookups, while this one lets the
// caller supply URLs from any source (e.g. CORE_GENESIS + bootstrap HTTP
// resolution for core validators when collecting ALFPs).
func OpenWebsocketConnectionsWithUrlMap(pubkeys []string, urlByPubkey map[string]string, wsConnMap map[string]*websocket.Conn, guards *WebsocketGuards) {
	guards.ConnMu.Lock()
	for id, conn := range wsConnMap {
		if conn != nil {
			_ = conn.Close()
			ScheduleWriteMuCleanup(guards, conn)
		}
		delete(wsConnMap, id)
	}
	guards.ConnMu.Unlock()

	for _, pubkey := range pubkeys {
		url := urlByPubkey[pubkey]
		if url == "" {
			continue
		}

		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		if err != nil {
			continue
		}

		guards.ConnMu.Lock()
		wsConnMap[pubkey] = conn
		guards.ConnMu.Unlock()
	}
}

func OpenWebsocketConnectionsWithQuorum(quorum []string, wsConnMap map[string]*websocket.Conn, guards *WebsocketGuards) {
	// Close and remove any existing connections
	guards.ConnMu.Lock()
	for id, conn := range wsConnMap {
		if conn != nil {
			_ = conn.Close()
			ScheduleWriteMuCleanup(guards, conn)
		}
		delete(wsConnMap, id)
	}
	guards.ConnMu.Unlock()

	// Establish new connections for each anchor in the quorum
	for _, anchorPubkey := range quorum {
		// Fetch anchor metadata
		raw, err := databases.APPROVEMENT_THREAD_METADATA.Get([]byte(anchorPubkey+"_ANCHOR_STORAGE"), nil)
		if err != nil {
			continue
		}

		// Parse metadata
		var anchorStorage structures.AnchorStorage
		if err := json.Unmarshal(raw, &anchorStorage); err != nil {
			continue
		}

		// Skip if no WS URL
		if anchorStorage.WssAnchorUrl == "" {
			continue
		}

		// Dial
		conn, _, err := websocket.DefaultDialer.Dial(anchorStorage.WssAnchorUrl, nil)
		if err != nil {
			continue
		}

		// Store in the shared map under lock
		guards.ConnMu.Lock()
		wsConnMap[anchorPubkey] = conn
		guards.ConnMu.Unlock()
	}
}

func NewQuorumWaiter(maxQuorumSize int, guards *WebsocketGuards) *QuorumWaiter {
	return &QuorumWaiter{
		responseCh: make(chan QuorumResponse, maxQuorumSize),
		done:       make(chan struct{}),
		answered:   make(map[string]struct{}, maxQuorumSize),
		responses:  make(map[string][]byte, maxQuorumSize),
		timer:      time.NewTimer(0),
		buf:        make([]string, 0, maxQuorumSize),
		failed:     make(map[string]struct{}),
		guards:     guards,
	}
}

func (qw *QuorumWaiter) closeDoneOnce() {
	select {
	case <-qw.done:
	default:
		close(qw.done)
	}
}

func (qw *QuorumWaiter) SendAndWait(
	ctx context.Context, message []byte, quorum []string,
	wsConnMap map[string]*websocket.Conn, majority int,
) (map[string][]byte, bool) {

	// Reset state
	qw.mu.Lock()
	for k := range qw.answered {
		delete(qw.answered, k)
	}
	for k := range qw.responses {
		delete(qw.responses, k)
	}
	for k := range qw.failed {
		delete(qw.failed, k)
	}
	qw.buf = qw.buf[:0]
	qw.mu.Unlock()

	// Arm/Reset timer
	if !qw.timer.Stop() {
		select {
		case <-qw.timer.C:
		default:
		}
	}
	qw.timer.Reset(time.Second)
	qw.done = make(chan struct{})

	// First send to the whole quorum
	qw.sendMessages(quorum, message, wsConnMap)

	for {
		select {
		case r := <-qw.responseCh:
			qw.mu.Lock()
			if _, ok := qw.answered[r.id]; !ok {
				qw.answered[r.id] = struct{}{}
				qw.responses[r.id] = r.msg
			}
			count := len(qw.answered)
			qw.mu.Unlock()

			if count >= majority {
				qw.closeDoneOnce()
				// copy responses
				qw.mu.Lock()
				out := make(map[string][]byte, len(qw.responses))
				for k, v := range qw.responses {
					out[k] = v
				}
				qw.mu.Unlock()

				// one-shot reconnect of failed nodes
				qw.reconnectFailed(wsConnMap)
				return out, true
			}

		case <-qw.timer.C:
			// resend to unanswered
			qw.mu.Lock()
			qw.buf = qw.buf[:0]
			for _, id := range quorum {
				if _, ok := qw.answered[id]; !ok {
					qw.buf = append(qw.buf, id)
				}
			}
			qw.mu.Unlock()

			if len(qw.buf) == 0 {
				qw.closeDoneOnce()
				qw.reconnectFailed(wsConnMap)
				return nil, false
			}
			qw.timer.Reset(time.Second)
			qw.sendMessages(qw.buf, message, wsConnMap)

		case <-ctx.Done():
			qw.closeDoneOnce()
			qw.reconnectFailed(wsConnMap)
			return nil, false
		}
	}
}

// SendAndWaitValidated is similar to SendAndWait but only counts validated responses toward the majority.
// The validate callback is called asynchronously in a goroutine for each response, allowing early exit
// once majority of validated responses is reached. This prevents attacks where malicious nodes respond
// quickly with invalid data to trigger early exit.
func (qw *QuorumWaiter) SendAndWaitValidated(
	ctx context.Context, message []byte, quorum []string,
	wsConnMap map[string]*websocket.Conn, majority int,
	validate func(id string, raw []byte) bool,
) (map[string][]byte, bool) {

	// Reset state
	qw.mu.Lock()
	for k := range qw.answered {
		delete(qw.answered, k)
	}
	for k := range qw.responses {
		delete(qw.responses, k)
	}
	for k := range qw.failed {
		delete(qw.failed, k)
	}
	qw.buf = qw.buf[:0]
	qw.mu.Unlock()

	// Separate tracking for validated responses
	validAnswered := make(map[string]struct{})
	validResponses := make(map[string][]byte)
	validMu := sync.Mutex{}

	// Channel for validated responses
	validCh := make(chan struct {
		id  string
		msg []byte
	}, len(quorum))

	// Arm/Reset timer
	if !qw.timer.Stop() {
		select {
		case <-qw.timer.C:
		default:
		}
	}
	qw.timer.Reset(time.Second)
	qw.done = make(chan struct{})

	// First send to the whole quorum
	qw.sendMessages(quorum, message, wsConnMap)

	for {
		select {
		case r := <-qw.responseCh:
			// Mark as answered (for resend logic)
			qw.mu.Lock()
			if _, ok := qw.answered[r.id]; !ok {
				qw.answered[r.id] = struct{}{}
				qw.responses[r.id] = r.msg
			}
			qw.mu.Unlock()

			// Validate asynchronously in goroutine
			go func(id string, raw []byte) {
				if validate(id, raw) {
					validMu.Lock()
					if _, ok := validAnswered[id]; !ok {
						validAnswered[id] = struct{}{}
						validResponses[id] = raw
						validMu.Unlock()

						// Send validated response to channel
						select {
						case validCh <- struct {
							id  string
							msg []byte
						}{id: id, msg: raw}:
						case <-qw.done:
						}
					} else {
						validMu.Unlock()
					}
				}
			}(r.id, r.msg)

		case <-validCh:
			// Check if we reached majority of validated responses
			validMu.Lock()
			validCount := len(validAnswered)
			validMu.Unlock()

			if validCount >= majority {
				qw.closeDoneOnce()
				// Copy validated responses
				validMu.Lock()
				out := make(map[string][]byte, len(validResponses))
				for k, v := range validResponses {
					out[k] = v
				}
				validMu.Unlock()

				// one-shot reconnect of failed nodes
				qw.reconnectFailed(wsConnMap)
				return out, true
			}

		case <-qw.timer.C:
			// resend to unanswered
			qw.mu.Lock()
			qw.buf = qw.buf[:0]
			for _, id := range quorum {
				if _, ok := qw.answered[id]; !ok {
					qw.buf = append(qw.buf, id)
				}
			}
			qw.mu.Unlock()

			if len(qw.buf) == 0 {
				// Check if we have enough validated responses before giving up
				validMu.Lock()
				validCount := len(validAnswered)
				validMu.Unlock()

				if validCount >= majority {
					qw.closeDoneOnce()
					validMu.Lock()
					out := make(map[string][]byte, len(validResponses))
					for k, v := range validResponses {
						out[k] = v
					}
					validMu.Unlock()
					qw.reconnectFailed(wsConnMap)
					return out, true
				}

				qw.closeDoneOnce()
				qw.reconnectFailed(wsConnMap)
				return nil, false
			}
			qw.timer.Reset(time.Second)
			qw.sendMessages(qw.buf, message, wsConnMap)

		case <-ctx.Done():
			// Check if we have enough validated responses before timeout
			validMu.Lock()
			validCount := len(validAnswered)
			validMu.Unlock()

			if validCount >= majority {
				qw.closeDoneOnce()
				validMu.Lock()
				out := make(map[string][]byte, len(validResponses))
				for k, v := range validResponses {
					out[k] = v
				}
				validMu.Unlock()
				qw.reconnectFailed(wsConnMap)
				return out, true
			}

			qw.closeDoneOnce()
			qw.reconnectFailed(wsConnMap)
			return nil, false
		}
	}
}

func (qw *QuorumWaiter) getWriteMuConn(c *websocket.Conn) *sync.Mutex {
	if c == nil {
		return &sync.Mutex{}
	}
	if m, ok := qw.guards.WriteMu.Load(c); ok {
		return m.(*sync.Mutex)
	}
	m := &sync.Mutex{}
	actual, _ := qw.guards.WriteMu.LoadOrStore(c, m)
	return actual.(*sync.Mutex)
}

func reconnectOnce(pubkey string, wsConnMap map[string]*websocket.Conn, guards *WebsocketGuards) {

	// Get anchor metadata
	raw, err := databases.APPROVEMENT_THREAD_METADATA.Get([]byte(pubkey+"_ANCHOR_STORAGE"), nil)
	if err != nil {
		return
	}
	var anchorStorage structures.AnchorStorage
	if err := json.Unmarshal(raw, &anchorStorage); err != nil || anchorStorage.WssAnchorUrl == "" {
		return
	}

	// Try a single dial attempt
	conn, _, err := websocket.DefaultDialer.Dial(anchorStorage.WssAnchorUrl, nil)
	if err != nil {
		return
	}

	// Store back into the shared map under lock
	guards.ConnMu.Lock()
	old := wsConnMap[pubkey]
	if old != nil {
		_ = old.Close()
	}
	wsConnMap[pubkey] = conn
	guards.ConnMu.Unlock()

	if old != nil {
		ScheduleWriteMuCleanup(guards, old)
	}
}

func (qw *QuorumWaiter) reconnectFailed(wsConnMap map[string]*websocket.Conn) {
	qw.mu.Lock()
	failedCopy := make([]string, 0, len(qw.failed))
	for id := range qw.failed {
		failedCopy = append(failedCopy, id)
	}
	// reset failed set for the next round
	for k := range qw.failed {
		delete(qw.failed, k)
	}
	qw.mu.Unlock()

	for _, id := range failedCopy {
		reconnectOnce(id, wsConnMap, qw.guards)
	}
}

func (qw *QuorumWaiter) sendMessages(targets []string, msg []byte, wsConnMap map[string]*websocket.Conn) {
	for _, id := range targets {
		// Read connection from the shared map under RLock
		qw.guards.ConnMu.RLock()
		conn, ok := wsConnMap[id]
		qw.guards.ConnMu.RUnlock()
		if !ok || conn == nil {
			// Mark as failed so we try to reconnect after the round
			qw.mu.Lock()
			qw.failed[id] = struct{}{}
			qw.mu.Unlock()
			continue
		}

		go func(id string, c *websocket.Conn) {
			// Gorilla websocket requires a single reader and a single writer per connection.
			// Serialize the whole request/response (write+read) for this conn.
			iomu := qw.getWriteMuConn(c)
			iomu.Lock()
			err := c.WriteMessage(websocket.TextMessage, msg)
			if err != nil {
				iomu.Unlock()
				// Mark as failed and remove the connection safely
				qw.mu.Lock()
				qw.failed[id] = struct{}{}
				qw.mu.Unlock()

				qw.guards.ConnMu.Lock()
				_ = c.Close()
				delete(wsConnMap, id)
				qw.guards.ConnMu.Unlock()
				ScheduleWriteMuCleanup(qw.guards, c)
				return
			}

			// Short read deadline for reply
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, raw, err := c.ReadMessage()
			iomu.Unlock()
			if err != nil {
				// Mark as failed and remove the connection safely
				qw.mu.Lock()
				qw.failed[id] = struct{}{}
				qw.mu.Unlock()

				qw.guards.ConnMu.Lock()
				_ = c.Close()
				delete(wsConnMap, id)
				qw.guards.ConnMu.Unlock()
				ScheduleWriteMuCleanup(qw.guards, c)
				return
			}

			select {
			case qw.responseCh <- QuorumResponse{id: id, msg: raw}:
			case <-qw.done:
			}
		}(id, conn)
	}
}
