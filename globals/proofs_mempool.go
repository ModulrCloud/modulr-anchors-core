package globals

import (
	"fmt"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

type epochProofMempool struct {
	sync.Mutex
	aggregatedAnchorRotationProofs     map[string]structures.AggregatedAnchorRotationProof     // proof for modulr-anchors-core logic to rotate anchors on demand
	aggregatedLeaderFinalizationProofs map[string]structures.AggregatedLeaderFinalizationProof // proof for modulr-core logic to finalize last block by leader
}

type Mempool struct {
	sync.RWMutex
	epochMempools map[int]*epochProofMempool
}

// Mempool to store two types of proofs, separated by epoch index to avoid cross-epoch mixing:

var MEMPOOL = Mempool{
	epochMempools: make(map[int]*epochProofMempool),
}

func anchorMempoolKey(proof structures.AggregatedAnchorRotationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
}

func leaderMempoolKey(proof structures.AggregatedLeaderFinalizationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Leader, proof.VotingStat.Index)
}

func newEpochProofMempool() *epochProofMempool {
	return &epochProofMempool{
		aggregatedAnchorRotationProofs:     make(map[string]structures.AggregatedAnchorRotationProof),
		aggregatedLeaderFinalizationProofs: make(map[string]structures.AggregatedLeaderFinalizationProof),
	}
}

func (mempool *Mempool) getEpochMempool(epochIndex int) *epochProofMempool {
	// Fast path: read lock for existing pool (common case).
	mempool.RLock()
	if pool, ok := mempool.epochMempools[epochIndex]; ok {
		mempool.RUnlock()
		return pool
	}
	mempool.RUnlock()

	// Slow path: create under write lock (double-check to avoid races).
	mempool.Lock()
	defer mempool.Unlock()
	if pool, ok := mempool.epochMempools[epochIndex]; ok {
		return pool
	}
	newPool := newEpochProofMempool()
	mempool.epochMempools[epochIndex] = newPool
	return newPool
}

func (mempool *Mempool) AddAggregatedAnchorRotationProof(proof structures.AggregatedAnchorRotationProof) {

	pool := mempool.getEpochMempool(proof.EpochIndex)

	pool.Lock()

	pool.aggregatedAnchorRotationProofs[anchorMempoolKey(proof)] = proof
	pool.Unlock()

}

func (mempool *Mempool) AddAggregatedLeaderFinalizationProof(proof structures.AggregatedLeaderFinalizationProof) {

	pool := mempool.getEpochMempool(proof.EpochIndex)

	pool.Lock()

	pool.aggregatedLeaderFinalizationProofs[leaderMempoolKey(proof)] = proof
	pool.Unlock()

}

func (mempool *Mempool) DrainAggregatedAnchorRotationProofs(epochIndex int) []structures.AggregatedAnchorRotationProof {

	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()
	defer pool.Unlock()

	if len(pool.aggregatedAnchorRotationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.AggregatedAnchorRotationProof, 0, len(pool.aggregatedAnchorRotationProofs))

	for _, proof := range pool.aggregatedAnchorRotationProofs {
		proofs = append(proofs, proof)
	}

	pool.aggregatedAnchorRotationProofs = make(map[string]structures.AggregatedAnchorRotationProof)

	return proofs

}

func (mempool *Mempool) ClearEpochProofs(epochIndex int) {

	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()

	pool.aggregatedAnchorRotationProofs = make(map[string]structures.AggregatedAnchorRotationProof)
	pool.aggregatedLeaderFinalizationProofs = make(map[string]structures.AggregatedLeaderFinalizationProof)

	pool.Unlock()

}

func (mempool *Mempool) RemoveEpochMempool(epochIndex int) {
	mempool.Lock()
	defer mempool.Unlock()

	delete(mempool.epochMempools, epochIndex)
}

// HasLeaderFinalizationProof reports whether an ALFP for (epochIndex, leader)
// is currently sitting in the mempool waiting to be included in a block.
// Used by AlfpProactivePullThread to avoid re-pulling a proof we already have.
func (mempool *Mempool) HasLeaderFinalizationProof(epochIndex int, leader string) bool {
	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()
	defer pool.Unlock()

	for _, proof := range pool.aggregatedLeaderFinalizationProofs {
		if proof.Leader == leader {
			return true
		}
	}
	return false
}

// RestoreAggregatedLeaderFinalizationProofs re-inserts proofs that were drained
// but failed to be persisted (e.g. block serialization or DB write failure).
// Existing entries with a higher voting-stat index for the same (leader, ...) key
// take precedence — we never downgrade the cached proof.
func (mempool *Mempool) RestoreAggregatedLeaderFinalizationProofs(epochIndex int, proofs []structures.AggregatedLeaderFinalizationProof) {
	if len(proofs) == 0 {
		return
	}
	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()
	defer pool.Unlock()

	for _, proof := range proofs {
		key := leaderMempoolKey(proof)
		if existing, ok := pool.aggregatedLeaderFinalizationProofs[key]; ok {
			if existing.VotingStat.Index >= proof.VotingStat.Index {
				continue
			}
		}
		pool.aggregatedLeaderFinalizationProofs[key] = proof
	}
}

// RestoreAggregatedAnchorRotationProofs is the AARP counterpart of
// RestoreAggregatedLeaderFinalizationProofs.
func (mempool *Mempool) RestoreAggregatedAnchorRotationProofs(epochIndex int, proofs []structures.AggregatedAnchorRotationProof) {
	if len(proofs) == 0 {
		return
	}
	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()
	defer pool.Unlock()

	for _, proof := range proofs {
		key := anchorMempoolKey(proof)
		if existing, ok := pool.aggregatedAnchorRotationProofs[key]; ok {
			if existing.VotingStat.Index >= proof.VotingStat.Index {
				continue
			}
		}
		pool.aggregatedAnchorRotationProofs[key] = proof
	}
}

func (mempool *Mempool) DrainAggregatedLeaderFinalizationProofs(epochIndex int) []structures.AggregatedLeaderFinalizationProof {

	pool := mempool.getEpochMempool(epochIndex)

	pool.Lock()
	defer pool.Unlock()

	if len(pool.aggregatedLeaderFinalizationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.AggregatedLeaderFinalizationProof, 0, len(pool.aggregatedLeaderFinalizationProofs))

	for _, proof := range pool.aggregatedLeaderFinalizationProofs {
		proofs = append(proofs, proof)
	}

	pool.aggregatedLeaderFinalizationProofs = make(map[string]structures.AggregatedLeaderFinalizationProof)

	return proofs

}
