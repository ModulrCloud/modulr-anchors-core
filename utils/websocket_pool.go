package utils

import (
	"encoding/json"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"github.com/gorilla/websocket"
)

type pooledConnection struct {
	conn     *websocket.Conn
	refCount int
}

type websocketPool struct {
	mu          sync.Mutex
	connections map[string]*pooledConnection
}

var globalWebsocketPool = websocketPool{connections: make(map[string]*pooledConnection)}

// AcquireWebsocketConnection returns an existing shared websocket connection for the given
// anchor public key or establishes a new one. Each successful call increments the reference count.
func AcquireWebsocketConnection(anchorPubKey string) *websocket.Conn {
	// First, try to reuse an existing live entry.
	globalWebsocketPool.mu.Lock()
	if entry, ok := globalWebsocketPool.connections[anchorPubKey]; ok && entry.conn != nil {
		entry.refCount++
		conn := entry.conn
		globalWebsocketPool.mu.Unlock()
		return conn
	}
	globalWebsocketPool.mu.Unlock()

	return establishAndStoreConnection(anchorPubKey)
}

// ReleaseWebsocketConnection decrements the reference count for the given anchor and closes the
// underlying connection when it is no longer used anywhere.
func ReleaseWebsocketConnection(anchorPubKey string) {
	globalWebsocketPool.mu.Lock()
	entry, ok := globalWebsocketPool.connections[anchorPubKey]
	if !ok {
		globalWebsocketPool.mu.Unlock()
		return
	}

	entry.refCount--
	if entry.refCount <= 0 {
		if entry.conn != nil {
			_ = entry.conn.Close()
		}
		delete(globalWebsocketPool.connections, anchorPubKey)
	}
	globalWebsocketPool.mu.Unlock()
}

// ReleaseQuorumConnections releases all connections associated with the provided map.
func ReleaseQuorumConnections(wsConnMap map[string]*websocket.Conn) {
	for anchorPubKey := range wsConnMap {
		ReleaseWebsocketConnection(anchorPubKey)
	}
}

// ReportWebsocketFailure marks the pooled connection as failed by closing it and resetting the
// stored pointer. Existing references will be released separately when callers clean up.
func ReportWebsocketFailure(anchorPubKey string) {
	globalWebsocketPool.mu.Lock()
	if entry, ok := globalWebsocketPool.connections[anchorPubKey]; ok {
		if entry.conn != nil {
			_ = entry.conn.Close()
			entry.conn = nil
		}
	}
	globalWebsocketPool.mu.Unlock()
}

// GetQuorumConnections ensures connections for the quorum anchors exist and returns a map that
// shares the pooled connections while incrementing reference counts for each.
func GetQuorumConnections(quorum []string) map[string]*websocket.Conn {
	wsConnMap := make(map[string]*websocket.Conn)
	for _, anchorPubKey := range quorum {
		if conn := AcquireWebsocketConnection(anchorPubKey); conn != nil {
			wsConnMap[anchorPubKey] = conn
		}
	}
	return wsConnMap
}

func establishAndStoreConnection(anchorPubKey string) *websocket.Conn {
	conn := dialAnchor(anchorPubKey)
	if conn == nil {
		return nil
	}

	globalWebsocketPool.mu.Lock()
	if entry, ok := globalWebsocketPool.connections[anchorPubKey]; ok {
		entry.refCount++
		if entry.conn == nil {
			entry.conn = conn
			globalWebsocketPool.mu.Unlock()
			return conn
		}
		globalWebsocketPool.mu.Unlock()
		_ = conn.Close()
		return entry.conn
	}

	globalWebsocketPool.connections[anchorPubKey] = &pooledConnection{conn: conn, refCount: 1}
	globalWebsocketPool.mu.Unlock()

	return conn
}

func dialAnchor(anchorPubKey string) *websocket.Conn {
	raw, err := databases.APPROVEMENT_THREAD_METADATA.Get([]byte(anchorPubKey+"_ANCHOR_STORAGE"), nil)
	if err != nil {
		return nil
	}

	var anchorStorage structures.AnchorStorage
	if err := json.Unmarshal(raw, &anchorStorage); err != nil || anchorStorage.WssAnchorUrl == "" {
		return nil
	}

	conn, _, err := websocket.DefaultDialer.Dial(anchorStorage.WssAnchorUrl, nil)
	if err != nil {
		return nil
	}

	return conn
}
