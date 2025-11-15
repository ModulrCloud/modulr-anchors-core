package threads

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
)

const defaultHealthCheckIntervalMs = 5000

type creatorSnapshot struct {
	Index int
	Hash  string
}

var creatorSnapshots = struct {
	sync.Mutex
	data map[string]creatorSnapshot
}{data: make(map[string]creatorSnapshot)}

// HealthCheckerThread monitors block creators for stalled progress.
func HealthCheckerThread() {
	intervalMs := globals.GENESIS.NetworkParameters.BlockCreatorsHealthCheckIntervalMs
	if intervalMs <= 0 {
		intervalMs = defaultHealthCheckIntervalMs
	}

	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		checkCreatorsHealth()
	}
}

func checkCreatorsHealth() {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	epochHandler := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandler()
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	if len(epochHandler.AnchorsRegistry) == 0 {
		return
	}

	for _, creator := range epochHandler.AnchorsRegistry {
		if utils.IsFinalizationProofsDisabled(epochHandler.Id, creator) {
			continue
		}

		votingStat, err := fetchCreatorVotingStat(epochHandler.Id, creator)
		if err != nil {
			utils.LogWithTime(
				fmt.Sprintf("health checker: failed to read voting stats for %s in epoch %d: %v", creator, epochHandler.Id, err),
				utils.YELLOW_COLOR,
			)
			continue
		}

		evaluateCreatorProgress(epochHandler.Id, creator, votingStat)
	}
}

func evaluateCreatorProgress(epochID int, creator string, current structures.VotingStat) {
	if current.Index < 0 {
		storeSnapshot(epochID, creator, current)
		return
	}

	key := snapshotKey(epochID, creator)

	creatorSnapshots.Lock()
	previous, hasPrevious := creatorSnapshots.data[key]
	creatorSnapshots.Unlock()

	if !hasPrevious {
		storeSnapshot(epochID, creator, current)
		return
	}

	if previous.Index == current.Index && previous.Hash == current.Hash {
		reason := fmt.Sprintf("health checker detected no progress for %s in epoch %d", creator, epochID)
		if err := utils.DisableFinalizationProofsForCreator(epochID, creator, reason); err != nil {
			utils.LogWithTime(
				fmt.Sprintf("health checker: failed to disable proofs for %s in epoch %d: %v", creator, epochID, err),
				utils.RED_COLOR,
			)
		} else {
			utils.LogWithTime(
				fmt.Sprintf("health checker: disabled proofs for %s in epoch %d", creator, epochID),
				utils.YELLOW_COLOR,
			)
		}
		creatorSnapshots.Lock()
		delete(creatorSnapshots.data, key)
		creatorSnapshots.Unlock()
		return
	}

	storeSnapshot(epochID, creator, current)
}

func storeSnapshot(epochID int, creator string, stat structures.VotingStat) {
	key := snapshotKey(epochID, creator)
	creatorSnapshots.Lock()
	creatorSnapshots.data[key] = creatorSnapshot{Index: stat.Index, Hash: stat.Hash}
	creatorSnapshots.Unlock()
}

func snapshotKey(epochID int, creator string) string {
	return strconv.Itoa(epochID) + ":" + creator
}

func fetchCreatorVotingStat(epochID int, creator string) (structures.VotingStat, error) {
	stat := structures.NewVotingStatTemplate()
	key := []byte(snapshotKey(epochID, creator))
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(key, nil)
	if err != nil {
		if errors.Is(err, ldbErrors.ErrNotFound) {
			return stat, nil
		}
		return stat, err
	}

	if len(raw) == 0 {
		return stat, nil
	}

	if err := json.Unmarshal(raw, &stat); err != nil {
		return stat, err
	}

	return stat, nil
}
