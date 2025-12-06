package globals

import (
	"fmt"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

// Mempool to store two types of proofs:

var mempool = struct {
	sync.Mutex
	anchorsRotationProofs     map[string]structures.AnchorRotationProof     // proof for modulr-anchors-core logic to rotate anchors on demand
	leadersFinalizationProofs map[string]structures.LeaderFinalizationProof // proof for modulr-core logic to finalize last block by leader
}{
	anchorsRotationProofs:     make(map[string]structures.AnchorRotationProof),
	leadersFinalizationProofs: make(map[string]structures.LeaderFinalizationProof),
}

func anchorRotationProofMempoolKey(proof structures.AnchorRotationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Anchor, proof.VotingStat.Index)
}

func leaderFinalizationProofMempoolKey(proof structures.LeaderFinalizationProof) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Leader, proof.VotingStat.Index)
}

func AddAnchorRotationProofToMempool(proof structures.AnchorRotationProof) {

	mempool.Lock()

	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}

	mempool.anchorsRotationProofs[anchorRotationProofMempoolKey(proof)] = proof
	mempool.Unlock()

}

func AddLeaderFinalizationProofToMempool(proof structures.LeaderFinalizationProof) {

	mempool.Lock()

	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}

	mempool.leadersFinalizationProofs[leaderFinalizationProofMempoolKey(proof)] = proof
	mempool.Unlock()

}

func DrainRotationProofsFromMempool() []structures.AnchorRotationProof {

	mempool.Lock()
	defer mempool.Unlock()

	if len(mempool.anchorsRotationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.AnchorRotationProof, 0, len(mempool.anchorsRotationProofs))

	for _, proof := range mempool.anchorsRotationProofs {
		proofs = append(proofs, proof)
	}

	mempool.anchorsRotationProofs = make(map[string]structures.AnchorRotationProof)

	return proofs

}

func DrainLeaderFinalizationProofsFromMempool() []structures.LeaderFinalizationProof {

	mempool.Lock()
	defer mempool.Unlock()

	if len(mempool.leadersFinalizationProofs) == 0 {
		return nil
	}

	proofs := make([]structures.LeaderFinalizationProof, 0, len(mempool.leadersFinalizationProofs))

	for _, proof := range mempool.leadersFinalizationProofs {
		proofs = append(proofs, proof)
	}

	mempool.leadersFinalizationProofs = make(map[string]structures.LeaderFinalizationProof)

	return proofs

}
