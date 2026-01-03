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
