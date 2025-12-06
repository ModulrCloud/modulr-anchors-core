package globals

import (
	"fmt"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

type Mempool struct {
	sync.Mutex
	aggregatedAnchorRotationProofs     map[string]structures.AggregatedAnchorRotationProof     // proof for modulr-anchors-core logic to rotate anchors on demand
	aggregatedLeaderFinalizationProofs map[string]structures.AggregatedLeaderFinalizationProof // proof for modulr-core logic to finalize last block by leader
}

// Mempool to store two types of proofs:

var MEMPOOL = Mempool{
	aggregatedAnchorRotationProofs:     make(map[string]structures.AggregatedAnchorRotationProof),
	aggregatedLeaderFinalizationProofs: make(map[string]structures.AggregatedLeaderFinalizationProof),
}

func anchorMempoolKey(proof structures.AggregatedAnchorRotationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
}

func leaderMempoolKey(proof structures.AggregatedLeaderFinalizationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Leader, proof.VotingStat.Index)
}

func (mempool *Mempool) AddAggregatedAnchorRotationProof(proof structures.AggregatedAnchorRotationProof) {

	mempool.Lock()

	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}

	mempool.aggregatedAnchorRotationProofs[anchorMempoolKey(proof)] = proof
	mempool.Unlock()

}

func (mempool *Mempool) AddAggregatedLeaderFinalizationProof(proof structures.AggregatedLeaderFinalizationProof) {

	mempool.Lock()

	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}

	mempool.aggregatedLeaderFinalizationProofs[leaderMempoolKey(proof)] = proof
	mempool.Unlock()

}

func (mempool *Mempool) DrainAggregatedAnchorRotationProofs() []structures.AggregatedAnchorRotationProof {

	mempool.Lock()
	defer mempool.Unlock()

	if len(mempool.aggregatedAnchorRotationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.AggregatedAnchorRotationProof, 0, len(mempool.aggregatedAnchorRotationProofs))

	for _, proof := range mempool.aggregatedAnchorRotationProofs {
		proofs = append(proofs, proof)
	}

	mempool.aggregatedAnchorRotationProofs = make(map[string]structures.AggregatedAnchorRotationProof)

	return proofs

}

func (mempool *Mempool) DrainAggregatedLeaderFinalizationProofs() []structures.AggregatedLeaderFinalizationProof {

	mempool.Lock()
	defer mempool.Unlock()

	if len(mempool.aggregatedLeaderFinalizationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.AggregatedLeaderFinalizationProof, 0, len(mempool.aggregatedLeaderFinalizationProofs))

	for _, proof := range mempool.aggregatedLeaderFinalizationProofs {
		proofs = append(proofs, proof)
	}

	mempool.aggregatedLeaderFinalizationProofs = make(map[string]structures.AggregatedLeaderFinalizationProof)

	return proofs

}
