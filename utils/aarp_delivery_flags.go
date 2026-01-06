package utils

import (
	"fmt"

	"github.com/modulrcloud/modulr-anchors-core/databases"
)

func aarpDisabledKey(epoch int, receiverAnchor string) []byte {
	return []byte(fmt.Sprintf("AARP_DISABLED:%d:%s", epoch, receiverAnchor))
}

// MarkAnchorDisabledByAarp marks that the network observed a valid AARP targeting receiverAnchor.
// Once this is set, delivery logic should stop sending any AARP payloads to that receiverAnchor.
func MarkAnchorDisabledByAarp(epoch int, receiverAnchor string) {
	if receiverAnchor == "" {
		return
	}
	_ = databases.FINALIZATION_VOTING_STATS.Put(aarpDisabledKey(epoch, receiverAnchor), []byte("1"), nil)
}

func IsAnchorDisabledByAarp(epoch int, receiverAnchor string) bool {
	if receiverAnchor == "" {
		return false
	}
	_, err := databases.FINALIZATION_VOTING_STATS.Get(aarpDisabledKey(epoch, receiverAnchor), nil)
	return err == nil
}
