package threads

import (
	"time"

	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"
)

// AnchorsPoDOutboxThread retries pending store messages to Anchors PoD until acknowledged.
func AnchorsPoDOutboxThread() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		_ = websocket_pack.FlushAnchorsPoDOutboxOnce(50)
	}
}
