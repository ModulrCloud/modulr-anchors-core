package utils

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/databases"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

// alfpIncludedKey returns the LevelDB key under which the inclusion marker
// for an ALFP belonging to (epochId, leader) is stored.
func alfpIncludedKey(epochId int, leader string) []byte {
	return []byte(fmt.Sprintf("%s%d:%s", constants.DBKeyPrefixAlfpIncluded, epochId, leader))
}

// MarkAlfpIncludedBatch enqueues inclusion markers for the given ALFPs
// into the provided LevelDB batch. The batch must target databases.EPOCH_DATA.
// This is used by BlocksGenerationThread so that ALFP inclusion markers are
// committed atomically with the block that included them.
func MarkAlfpIncludedBatch(batch *leveldb.Batch, epochId int, leaders []string) {
	if batch == nil {
		return
	}
	for _, leader := range leaders {
		batch.Put(alfpIncludedKey(epochId, leader), []byte("TRUE"))
	}
}

// IsAlfpIncluded reports whether an inclusion marker for (epochId, leader)
// has been stored. It returns false on any read error so callers do not
// mistakenly treat missing markers as included.
func IsAlfpIncluded(epochId int, leader string) bool {
	_, err := databases.EPOCH_DATA.Get(alfpIncludedKey(epochId, leader), nil)
	return err == nil
}

// DeleteAlfpInclusionMarkersForEpoch removes all inclusion markers for the
// given epoch. Called when an epoch is dropped from the supported window.
// Errors are logged but not propagated since this is a best-effort cleanup.
func DeleteAlfpInclusionMarkersForEpoch(epochId int) {
	prefix := []byte(constants.DBKeyPrefixAlfpIncluded + strconv.Itoa(epochId) + ":")

	iter := databases.EPOCH_DATA.NewIterator(util.BytesPrefix(prefix), nil)
	defer iter.Release()

	batch := new(leveldb.Batch)
	for iter.Next() {
		batch.Delete(append([]byte(nil), iter.Key()...))
	}
	if err := iter.Error(); err != nil {
		LogWithTime(
			fmt.Sprintf("ALFP inclusion cleanup: iterator error for epoch %d: %v", epochId, err),
			YELLOW_COLOR,
		)
		return
	}

	if batch.Len() == 0 {
		return
	}

	if err := databases.EPOCH_DATA.Write(batch, nil); err != nil {
		LogWithTime(
			fmt.Sprintf("ALFP inclusion cleanup: failed to delete markers for epoch %d: %v", epochId, err),
			YELLOW_COLOR,
		)
	}
}

// AlfpInclusionMarkerExists is a convenience helper for tests/diagnostics.
// It avoids leaking the LevelDB key format outside this file.
func AlfpInclusionMarkerExists(epochId int, leader string) bool {
	if strings.TrimSpace(leader) == "" || epochId < 0 {
		return false
	}
	return IsAlfpIncluded(epochId, leader)
}
