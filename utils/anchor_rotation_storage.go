package utils

import (
	"encoding/json"
	"errors"
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
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
	return databases.FINALIZATION_VOTING_STATS.Put(aggregatedAnchorRotationProofKey(proof.EpochIndex, proof.Anchor), payload, nil)
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
