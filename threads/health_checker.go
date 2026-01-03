package threads

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

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
		intervalMs = 5000
	}

	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		checkCreatorsHealth()
	}
}

func checkCreatorsHealth() {
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	totalEpochs := len(epochHandlers)
	totalCreators := 0
	activeCreators := 0
	stalledCreators := 0

	for _, epochHandler := range epochHandlers {
		if len(epochHandler.AnchorsRegistry) == 0 {
			continue
		}

		totalCreators += len(epochHandler.AnchorsRegistry)
		for _, creator := range epochHandler.AnchorsRegistry {
			if utils.IsFinalizationProofsDisabled(epochHandler.Id, creator) {
				continue
			}

			activeCreators++
			votingStat, err := utils.ReadVotingStat(epochHandler.Id, creator)
			if err != nil {
				utils.LogWithTime(
					fmt.Sprintf("Health checker: failed to read voting stats for %s in epoch %d: %v", creator, epochHandler.Id, err),
					utils.YELLOW_COLOR,
				)
				continue
			}

			if evaluateCreatorProgress(epochHandler.Id, creator, votingStat) {
				stalledCreators++
			}
		}
	}

	summaryColor := utils.GREEN_COLOR
	metrics := []string{
		utils.ColoredMetric("Epochs", totalEpochs, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Total_creators", totalCreators, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Active_creators", activeCreators, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Stalled_creators", stalledCreators, utils.CYAN_COLOR, summaryColor),
	}
	utils.LogWithTime(
		fmt.Sprintf("Health checker: Iteration summary %s", strings.Join(metrics, " ")),
		summaryColor,
	)
}

func evaluateCreatorProgress(epochID int, creator string, current structures.VotingStat) bool {

	key := snapshotKey(epochID, creator)

	creatorSnapshots.Lock()
	previous, hasPrevious := creatorSnapshots.data[key]
	creatorSnapshots.Unlock()

	if !hasPrevious {
		storeSnapshot(epochID, creator, current)
		return false
	}

	if previous.Index == current.Index && previous.Hash == current.Hash {
		if err := utils.DisableFinalizationProofsForCreator(epochID, creator); err != nil {
			utils.LogWithTime(
				fmt.Sprintf("Health checker: failed to disable proofs for %s in epoch %d: %v", creator, epochID, err),
				utils.RED_COLOR,
			)
		} else {
			utils.LogWithTime(
				fmt.Sprintf("Health checker: disabled proofs for %s in epoch %d", creator, epochID),
				utils.YELLOW_COLOR,
			)
		}
		creatorSnapshots.Lock()
		delete(creatorSnapshots.data, key)
		creatorSnapshots.Unlock()
		return true
	}

	storeSnapshot(epochID, creator, current)
	return false
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

// DeleteHealthSnapshotsForEpoch removes all cached health snapshots for the provided epoch.
// Without this cleanup, snapshots for dropped epochs accumulate in memory indefinitely.
func DeleteHealthSnapshotsForEpoch(epochID int) {
	prefix := strconv.Itoa(epochID) + ":"
	creatorSnapshots.Lock()
	for k := range creatorSnapshots.data {
		if strings.HasPrefix(k, prefix) {
			delete(creatorSnapshots.data, k)
		}
	}
	creatorSnapshots.Unlock()
}
