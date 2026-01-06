package threads

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/syndtr/goleveldb/leveldb/util"
)

func aarpKeyPrefix(epoch int) []byte {
	return []byte("AARP:" + strconv.Itoa(epoch) + ":")
}

func loadAllAarpsForEpoch(epochHandler *structures.EpochDataHandler) []structures.AggregatedAnchorRotationProof {
	if epochHandler == nil {
		return nil
	}
	prefix := aarpKeyPrefix(epochHandler.Id)
	it := databases.FINALIZATION_VOTING_STATS.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	out := make([]structures.AggregatedAnchorRotationProof, 0)
	for it.Next() {
		var proof structures.AggregatedAnchorRotationProof
		if err := json.Unmarshal(it.Value(), &proof); err != nil {
			continue
		}
		// Defensive: verify before using.
		if err := utils.VerifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
			continue
		}
		out = append(out, proof)
	}
	return out
}

// AarpDeliveryThread periodically re-broadcasts stored AARPs until they are observed in blocks of each receiver anchor.
//
// Stop condition for sending AARP targeting X to receiver Y:
// - Trigger #1: AARP_PRESENCE(epoch, blockCreator=Y, rotatedAnchor=X) exists
// - Trigger #2: we have observed any valid AARP targeting Y (so we stop sending anything to Y)
func AarpDeliveryThread() {
	client := &http.Client{Timeout: 5 * time.Second}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
		epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
		handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

		for idx := range epochHandlers {
			epochHandler := &epochHandlers[idx]
			deliverAarpsForEpoch(epochHandler, client)
		}
	}
}

func deliverAarpsForEpoch(epochHandler *structures.EpochDataHandler, client *http.Client) {
	if epochHandler == nil || client == nil {
		return
	}

	proofs := loadAllAarpsForEpoch(epochHandler)
	if len(proofs) == 0 {
		return
	}

	receivers := utils.GetQuorumUrlsAndPubkeys(epochHandler)
	if len(receivers) == 0 {
		return
	}

	for _, proof := range proofs {
		// Keep local mempool warm as well (covers local restart / mempool loss).
		globals.MEMPOOL.AddAggregatedAnchorRotationProof(proof)

		payload := structures.AcceptAggregatedAnchorRotationProofRequest{
			AggregatedRotationProofs: []structures.AggregatedAnchorRotationProof{proof},
		}
		body, err := json.Marshal(payload)
		if err != nil {
			continue
		}

		rotatedAnchor := proof.Anchor // target X

		for _, receiver := range receivers {
			receiverPk := receiver.PubKey // receiver Y
			receiverUrl := receiver.Url

			if receiverPk == "" || receiverUrl == "" {
				continue
			}
			// Don't send to self.
			if strings.EqualFold(receiverPk, globals.CONFIGURATION.PublicKey) {
				continue
			}

			// Trigger #2: if receiver is under rotation, stop sending anything to it.
			if utils.IsAnchorDisabledByAarp(epochHandler.Id, receiverPk) {
				continue
			}

			// Trigger #1: if receiver already included rotatedAnchor proof in its blocks, stop sending to it.
			if blockId, _ := utils.LoadAggregatedAnchorRotationProofPresence(epochHandler.Id, receiverPk, rotatedAnchor); blockId != "" {
				continue
			}

			endpoint := strings.TrimRight(receiverUrl, "/") + "/accept_aggregated_anchor_rotation_proof"
			req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_ = resp.Body.Close()

			// We deliberately don't require 200 here: even a temporary failure will be retried on next tick.
		}
	}
}
