package utils

import (
	"strconv"

	"github.com/modulrcloud/modulr-anchors-core/globals"
)

// ComputeCoreQuorumFromGenesis deterministically computes the modulr-core quorum
// for epoch 0 using the same algorithm as modulr-core itself.
// This allows anchors to know the initial core quorum without running a core node.
func ComputeCoreQuorumFromGenesis() []string {

	cg := &globals.CORE_GENESIS

	hashInput := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + cg.NetworkId + strconv.FormatUint(cg.FirstEpochStartTimestamp, 10)

	initEpochHash := Blake3(hashInput)

	pubkeys := make([]string, 0, len(cg.Validators))
	stakes := make([]uint64, 0, len(cg.Validators))
	var totalStakeSum uint64

	for _, v := range cg.Validators {
		pubkeys = append(pubkeys, v.Pubkey)
		stakes = append(stakes, v.TotalStaked)
		totalStakeSum += v.TotalStaked
	}

	if totalStakeSum == 0 || len(pubkeys) == 0 {
		return []string{}
	}

	quorumSize := cg.NetworkParameters.QuorumSize

	if len(pubkeys) <= quorumSize {
		result := make([]string, len(pubkeys))
		copy(result, pubkeys)
		return result
	}

	hashOfMetadata := Blake3(initEpochHash)

	tree := NewStakeFenwickTree(stakes)
	quorum := make([]string, 0, quorumSize)

	for i := 0; i < quorumSize && totalStakeSum > 0; i++ {
		hashHex := Blake3(hashOfMetadata + "_" + strconv.Itoa(i))
		r := HashHexToUint64(hashHex) % totalStakeSum

		idx := tree.FindByWeight(r)
		quorum = append(quorum, pubkeys[idx])
		totalStakeSum -= stakes[idx]
		tree.Remove(idx, stakes[idx])
	}

	return quorum
}
