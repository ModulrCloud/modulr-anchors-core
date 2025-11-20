package handlers

import (
	"fmt"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

var extraDataMempool = struct {
	sync.Mutex
	rotationProofs           map[string]structures.AnchorRotationProofBundle
	leaderFinalizationProofs map[string]structures.LeaderFinalizationProofBundle
}{rotationProofs: make(map[string]structures.AnchorRotationProofBundle), leaderFinalizationProofs: make(map[string]structures.LeaderFinalizationProofBundle)}

func rotationProofMempoolKey(proof structures.AnchorRotationProofBundle) string {
	return fmt.Sprintf("%d:%s:%d", proof.EpochIndex, proof.Creator, proof.VotingStat.Index)
}

func leaderFinalizationMempoolKey(proof structures.LeaderFinalizationProofBundle) string {
	return fmt.Sprintf("%s:%s:%d", proof.ChainId, proof.Leader, proof.VotingStat.Index)
}

func AddRotationProofToMempool(proof structures.AnchorRotationProofBundle) {
	extraDataMempool.Lock()
	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}
	extraDataMempool.rotationProofs[rotationProofMempoolKey(proof)] = proof
	extraDataMempool.Unlock()
}

func AddLeaderFinalizationProofToMempool(proof structures.LeaderFinalizationProofBundle) {
	extraDataMempool.Lock()
	if proof.Signatures == nil {
		proof.Signatures = map[string]string{}
	}
	extraDataMempool.leaderFinalizationProofs[leaderFinalizationMempoolKey(proof)] = proof
	extraDataMempool.Unlock()
}

func DrainRotationProofsFromMempool() []structures.AnchorRotationProofBundle {
	extraDataMempool.Lock()
	defer extraDataMempool.Unlock()
	if len(extraDataMempool.rotationProofs) == 0 {
		return nil
	}
	proofs := make([]structures.AnchorRotationProofBundle, 0, len(extraDataMempool.rotationProofs))
	for _, proof := range extraDataMempool.rotationProofs {
		proofs = append(proofs, proof)
	}
	extraDataMempool.rotationProofs = make(map[string]structures.AnchorRotationProofBundle)
	return proofs
}

func DrainLeaderFinalizationProofsFromMempool() []structures.LeaderFinalizationProofBundle {
	extraDataMempool.Lock()
	defer extraDataMempool.Unlock()
	if len(extraDataMempool.leaderFinalizationProofs) == 0 {
		return nil
	}
	proofs := make([]structures.LeaderFinalizationProofBundle, 0, len(extraDataMempool.leaderFinalizationProofs))
	for _, proof := range extraDataMempool.leaderFinalizationProofs {
		proofs = append(proofs, proof)
	}
	extraDataMempool.leaderFinalizationProofs = make(map[string]structures.LeaderFinalizationProofBundle)
	return proofs
}
