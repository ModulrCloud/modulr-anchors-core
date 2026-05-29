package routes

import (
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"
)

const recoveryViewMaxCatchupHops = 256

type recoveryCoreQuorumView struct {
	LatestEpochId int
	FromEpochId   int
	Source        string
	Epochs        map[int]*structures.CoreEpochData
	Proofs        map[int]*structures.AggregatedEpochRotationProof
}

var (
	recoveryViewMu     sync.RWMutex
	recoveryViewCached *recoveryCoreQuorumView
)

// ResetRecoveryCoreQuorumViewForTest clears the in-memory recovery view cache
// so tests can exercise catch-up from different external sources independently.
func ResetRecoveryCoreQuorumViewForTest() {
	recoveryViewMu.Lock()
	defer recoveryViewMu.Unlock()

	recoveryViewCached = nil
}

func getRecoveryCoreQuorumView(targetEpochId int) *recoveryCoreQuorumView {
	if !recoveryViewMu.TryLock() {
		return recoveryViewSnapshot()
	}
	defer recoveryViewMu.Unlock()

	view := recoveryViewCached
	if view == nil {
		view = initRecoveryCoreQuorumView()
	}
	if view == nil {
		return nil
	}

	if targetEpochId > 0 && view.LatestEpochId >= targetEpochId {
		recoveryViewCached = view
		return cloneRecoveryCoreQuorumView(view)
	}

	catchUpRecoveryCoreQuorumView(view, targetEpochId)
	recoveryViewCached = view

	return cloneRecoveryCoreQuorumView(view)
}

func recoveryViewSnapshot() *recoveryCoreQuorumView {
	if !recoveryViewMu.TryRLock() {
		return initRecoveryCoreQuorumView()
	}
	defer recoveryViewMu.RUnlock()

	if recoveryViewCached != nil {
		return cloneRecoveryCoreQuorumView(recoveryViewCached)
	}

	return initRecoveryCoreQuorumView()
}

func initRecoveryCoreQuorumView() *recoveryCoreQuorumView {
	state := utils.LoadCoreQuorumState()
	if state == nil {
		return nil
	}

	epochData := utils.LoadCoreEpochData(state.LatestEpochId)
	if epochData == nil {
		return nil
	}

	view := &recoveryCoreQuorumView{
		LatestEpochId: state.LatestEpochId,
		FromEpochId:   state.LatestEpochId,
		Source:        "local",
		Epochs:        make(map[int]*structures.CoreEpochData),
		Proofs:        make(map[int]*structures.AggregatedEpochRotationProof),
	}
	view.Epochs[epochData.EpochId] = cloneCoreEpochData(epochData)

	if state.LatestEpochId > 0 {
		if proof := utils.LoadAggregatedEpochRotationProof(state.LatestEpochId); proof != nil {
			view.Proofs[state.LatestEpochId] = proof
		}
	}

	return view
}

func catchUpRecoveryCoreQuorumView(view *recoveryCoreQuorumView, targetEpochId int) {
	for hops := 0; hops < recoveryViewMaxCatchupHops; hops++ {
		if targetEpochId > 0 && view.LatestEpochId >= targetEpochId {
			return
		}

		currentEpochData := view.Epochs[view.LatestEpochId]
		if currentEpochData == nil {
			return
		}

		nextEpochId := view.LatestEpochId + 1
		proof := recoveryViewFetchProof(view.LatestEpochId, nextEpochId)
		if proof == nil {
			return
		}
		if !utils.VerifyAggregatedEpochRotationProofAgainstEpoch(proof, currentEpochData) {
			return
		}

		view.Proofs[proof.NextEpochId] = proof
		view.Epochs[proof.NextEpochId] = &structures.CoreEpochData{
			EpochId:         proof.NextEpochId,
			EpochHash:       proof.EpochData.NextEpochHash,
			Quorum:          append([]string(nil), proof.EpochData.NextEpochQuorum...),
			LeadersSequence: append([]string(nil), proof.EpochData.NextEpochLeadersSequence...),
		}
		view.LatestEpochId = proof.NextEpochId
		view.Source = "memory_catchup"
	}
}

func recoveryViewFetchProof(currentEpochId, nextEpochId int) *structures.AggregatedEpochRotationProof {
	if proof := utils.LoadAggregatedEpochRotationProof(nextEpochId); proof != nil {
		return proof
	}

	if proof := websocket_pack.GetAggregatedEpochRotationProofFromPoD(currentEpochId); proof != nil {
		return proof
	}

	return websocket_pack.GetAggregatedEpochRotationProofFromAnchorsByHTTPUnverified(nextEpochId)
}

func cloneRecoveryCoreQuorumView(view *recoveryCoreQuorumView) *recoveryCoreQuorumView {
	if view == nil {
		return nil
	}

	clone := &recoveryCoreQuorumView{
		LatestEpochId: view.LatestEpochId,
		FromEpochId:   view.FromEpochId,
		Source:        view.Source,
		Epochs:        make(map[int]*structures.CoreEpochData, len(view.Epochs)),
		Proofs:        make(map[int]*structures.AggregatedEpochRotationProof, len(view.Proofs)),
	}
	for epochId, epochData := range view.Epochs {
		clone.Epochs[epochId] = cloneCoreEpochData(epochData)
	}
	for epochId, proof := range view.Proofs {
		clone.Proofs[epochId] = proof
	}

	return clone
}

func cloneCoreEpochData(data *structures.CoreEpochData) *structures.CoreEpochData {
	if data == nil {
		return nil
	}

	return &structures.CoreEpochData{
		EpochId:         data.EpochId,
		EpochHash:       data.EpochHash,
		Quorum:          append([]string(nil), data.Quorum...),
		LeadersSequence: append([]string(nil), data.LeadersSequence...),
	}
}
