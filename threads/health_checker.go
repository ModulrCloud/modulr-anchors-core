package threads

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/gorilla/websocket"
)

type AnchorHealthSnapshot struct {
	Index int
	Hash  string
}

var HEALTH_SNAPSHOTS_PER_ANCHOR = struct {
	sync.Mutex
	data map[string]AnchorHealthSnapshot
}{data: make(map[string]AnchorHealthSnapshot)}

// HealthCheckerThread monitors anchors for stalled progress.
func HealthCheckerThread() {
	intervalMs := globals.GENESIS.NetworkParameters.BlockCreatorsHealthCheckIntervalMs
	if intervalMs <= 0 {
		intervalMs = 5000
	}

	ticker := time.NewTicker(time.Duration(intervalMs) * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		checkAnchorHealth()
	}
}

func checkAnchorHealth() {
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

			if evaluateAnchorProgressWithPull(&epochHandler, creator, votingStat) {
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

func evaluateAnchorProgressWithPull(epochHandler *structures.EpochDataHandler, creator string, current structures.VotingStat) bool {

	epochID := epochHandler.Id

	key := snapshotKey(epochID, creator)

	HEALTH_SNAPSHOTS_PER_ANCHOR.Lock()
	previous, hasPrevious := HEALTH_SNAPSHOTS_PER_ANCHOR.data[key]
	HEALTH_SNAPSHOTS_PER_ANCHOR.Unlock()

	if !hasPrevious {
		storeSnapshot(epochID, creator, current)
		return false
	}

	if previous.Index == current.Index && previous.Hash == current.Hash {
		if updated, newStat := tryPullVotingStatFromQuorum(epochHandler, creator, current); updated {
			storeSnapshot(epochID, creator, newStat)
			return false
		}

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
		HEALTH_SNAPSHOTS_PER_ANCHOR.Lock()
		delete(HEALTH_SNAPSHOTS_PER_ANCHOR.data, key)
		HEALTH_SNAPSHOTS_PER_ANCHOR.Unlock()
		return true
	}

	storeSnapshot(epochID, creator, current)
	return false
}

func storeSnapshot(epochID int, creator string, stat structures.VotingStat) {
	key := snapshotKey(epochID, creator)
	HEALTH_SNAPSHOTS_PER_ANCHOR.Lock()
	HEALTH_SNAPSHOTS_PER_ANCHOR.data[key] = AnchorHealthSnapshot{Index: stat.Index, Hash: stat.Hash}
	HEALTH_SNAPSHOTS_PER_ANCHOR.Unlock()
}

func tryPullVotingStatFromQuorum(epochHandler *structures.EpochDataHandler, creator string, current structures.VotingStat) (bool, structures.VotingStat) {

	peers := epochHandler.Quorum
	if len(peers) == 0 {
		peers = epochHandler.AnchorsRegistry
	}
	if len(peers) == 0 {
		return false, current
	}

	req := websocket_pack.WsVotingStatRequest{
		Route:      "get_voting_stat",
		EpochIndex: epochHandler.Id,
		Creator:    creator,
	}
	msg, err := json.Marshal(req)
	if err != nil {
		return false, current
	}

	connections := make(map[string]*websocket.Conn)
	var connMu sync.RWMutex
	utils.OpenWebsocketConnectionsWithQuorum(peers, connections, &connMu)
	defer func() {
		connMu.Lock()
		for _, c := range connections {
			if c != nil {
				_ = c.Close()
			}
		}
		connMu.Unlock()
	}()

	needed := len(peers)
	if needed > 3 {
		needed = 3
	}
	if needed <= 0 {
		needed = 1
	}

	waiter := utils.NewQuorumWaiter(len(peers))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	responses, ok := waiter.SendAndWait(ctx, msg, peers, connections, &connMu, needed)
	if !ok || len(responses) == 0 {
		return false, current
	}

	best := current
	found := false
	for _, raw := range responses {
		var resp websocket_pack.WsVotingStatResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			continue
		}
		if resp.Status != "OK" || resp.EpochIndex != epochHandler.Id || resp.Creator != creator {
			continue
		}
		candidate := resp.VotingStat
		if candidate.Index <= best.Index {
			continue
		}
		// Validate candidate (protect against bad/malicious data).
		if candidate.Afp.BlockId != "" && candidate.Hash == candidate.Afp.BlockHash && utils.VerifyAggregatedFinalizationProof(&candidate.Afp, epochHandler) {
			best = candidate
			found = true
		}
	}

	if !found || best.Index <= current.Index {
		return false, current
	}

	// Protect against races with other writers (e.g. GetFinalizationProof / rotation collector):
	// - serialize updates per (epoch, creator)
	// - re-read latest and only upgrade (never downgrade)
	mutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(epochHandler.Id, creator)
	mutex.Lock()
	defer mutex.Unlock()

	latest, err := utils.ReadVotingStat(epochHandler.Id, creator)
	if err != nil {
		return false, current
	}
	if best.Index <= latest.Index {
		return false, latest
	}

	if err := utils.StoreVotingStat(epochHandler.Id, creator, best); err != nil {
		return false, current
	}

	utils.LogWithTime(
		fmt.Sprintf("Health checker: pulled fresher voting stat for %s in epoch %d (index %d -> %d)", creator, epochHandler.Id, latest.Index, best.Index),
		utils.CYAN_COLOR,
	)

	return true, best
}

func snapshotKey(epochID int, creator string) string {
	return strconv.Itoa(epochID) + ":" + creator
}

// DeleteHealthSnapshotsForEpoch removes all cached health snapshots for the provided epoch.
// Without this cleanup, snapshots for dropped epochs accumulate in memory indefinitely.
func DeleteHealthSnapshotsForEpoch(epochID int) {
	prefix := strconv.Itoa(epochID) + ":"
	HEALTH_SNAPSHOTS_PER_ANCHOR.Lock()
	for k := range HEALTH_SNAPSHOTS_PER_ANCHOR.data {
		if strings.HasPrefix(k, prefix) {
			delete(HEALTH_SNAPSHOTS_PER_ANCHOR.data, k)
		}
	}
	HEALTH_SNAPSHOTS_PER_ANCHOR.Unlock()
}
