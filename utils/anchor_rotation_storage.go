package utils

import (
	"encoding/json"
	"errors"
	"strconv"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/util"
)

func aggregatedAnchorRotationProofKey(epoch int, creator string) []byte {
	return []byte("AARP:" + strconv.Itoa(epoch) + ":" + creator)
}

func aggregatedAnchorRotationProofPresenceKey(epoch int, blockCreator, rotatedAnchor string) []byte {
	return []byte("AARP_PRESENCE:" + strconv.Itoa(epoch) + ":" + blockCreator + ":" + rotatedAnchor)
}

func StoreAggregatedAnchorRotationProof(proof structures.AggregatedAnchorRotationProof) error {
	payload, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if err := databases.FINALIZATION_VOTING_STATS.Put(aggregatedAnchorRotationProofKey(proof.EpochIndex, proof.Anchor), payload, nil); err != nil {
		return err
	}
	cacheAarpProof(proof)
	return nil
}

func StoreAggregatedAnchorRotationProofPresence(epoch int, blockCreator, rotatedAnchor, blockId string) error {
	return databases.FINALIZATION_VOTING_STATS.Put(aggregatedAnchorRotationProofPresenceKey(epoch, blockCreator, rotatedAnchor), []byte(blockId), nil)
}

func LoadAggregatedAnchorRotationProofPresence(epoch int, blockCreator, rotatedAnchor string) (string, error) {
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(aggregatedAnchorRotationProofPresenceKey(epoch, blockCreator, rotatedAnchor), nil)
	if err != nil {
		if errors.Is(err, ldbErrors.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	if len(raw) == 0 {
		return "", nil
	}
	return string(raw), nil
}

func LoadAggregatedAnchorRotationProof(epoch int, creator string) (structures.AggregatedAnchorRotationProof, error) {
	var proof structures.AggregatedAnchorRotationProof
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(aggregatedAnchorRotationProofKey(epoch, creator), nil)
	if err != nil {
		if errors.Is(err, ldbErrors.ErrNotFound) {
			return proof, nil
		}
		return proof, err
	}
	if len(raw) == 0 {
		return proof, nil
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return proof, err
	}
	return proof, nil
}

func HasAggregatedAnchorRotationProof(epoch int, creator string) bool {
	if _, err := databases.FINALIZATION_VOTING_STATS.Get(aggregatedAnchorRotationProofKey(epoch, creator), nil); err == nil {
		return true
	}
	return false
}

type aarpCacheState struct {
	sync.RWMutex
	loaded map[int]bool
	proofs map[int]map[string]structures.AggregatedAnchorRotationProof
}

var AARP_CACHE = aarpCacheState{
	loaded: make(map[int]bool),
	proofs: make(map[int]map[string]structures.AggregatedAnchorRotationProof),
}

func aarpCacheKey(proof structures.AggregatedAnchorRotationProof) string {
	return strconv.Itoa(proof.EpochIndex) + ":" + proof.Anchor + ":" + strconv.Itoa(proof.VotingStat.Index)
}

func cacheAarpProof(proof structures.AggregatedAnchorRotationProof) {
	AARP_CACHE.Lock()
	if _, ok := AARP_CACHE.proofs[proof.EpochIndex]; !ok {
		AARP_CACHE.proofs[proof.EpochIndex] = make(map[string]structures.AggregatedAnchorRotationProof)
	}
	AARP_CACHE.proofs[proof.EpochIndex][aarpCacheKey(proof)] = proof
	AARP_CACHE.Unlock()
}

// GetAggregatedAnchorRotationProofs returns cached proofs for the epoch.
// The cache is populated on first call by scanning LevelDB once.
func GetAggregatedAnchorRotationProofs(epochHandler *structures.EpochDataHandler) []structures.AggregatedAnchorRotationProof {
	if epochHandler == nil || epochHandler.Id < 0 {
		return nil
	}
	epochID := epochHandler.Id

	AARP_CACHE.RLock()
	if AARP_CACHE.loaded[epochID] {
		cached := AARP_CACHE.proofs[epochID]
		AARP_CACHE.RUnlock()
		if len(cached) == 0 {
			return nil
		}
		out := make([]structures.AggregatedAnchorRotationProof, 0, len(cached))
		for _, proof := range cached {
			out = append(out, proof)
		}
		return out
	}
	AARP_CACHE.RUnlock()

	prefix := []byte("AARP:" + strconv.Itoa(epochID) + ":")
	it := databases.FINALIZATION_VOTING_STATS.NewIterator(util.BytesPrefix(prefix), nil)
	defer it.Release()

	loaded := make(map[string]structures.AggregatedAnchorRotationProof)
	for it.Next() {
		var proof structures.AggregatedAnchorRotationProof
		if err := json.Unmarshal(it.Value(), &proof); err != nil {
			continue
		}
		// Defensive: verify before caching.
		if err := VerifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
			continue
		}
		loaded[aarpCacheKey(proof)] = proof
	}

	AARP_CACHE.Lock()
	if _, ok := AARP_CACHE.proofs[epochID]; !ok {
		AARP_CACHE.proofs[epochID] = make(map[string]structures.AggregatedAnchorRotationProof)
	}
	for k, v := range loaded {
		AARP_CACHE.proofs[epochID][k] = v
	}
	AARP_CACHE.loaded[epochID] = true
	AARP_CACHE.Unlock()

	if len(loaded) == 0 {
		return nil
	}
	out := make([]structures.AggregatedAnchorRotationProof, 0, len(loaded))
	for _, proof := range loaded {
		out = append(out, proof)
	}
	return out
}

// ClearAggregatedAnchorRotationProofCache removes cached proofs for a dropped epoch.
func ClearAggregatedAnchorRotationProofCache(epochID int) {
	if epochID < 0 {
		return
	}
	AARP_CACHE.Lock()
	delete(AARP_CACHE.loaded, epochID)
	delete(AARP_CACHE.proofs, epochID)
	AARP_CACHE.Unlock()
}
