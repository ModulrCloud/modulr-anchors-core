package utils

import (
	"encoding/json"
	"errors"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	ldbErrors "github.com/syndtr/goleveldb/leveldb/errors"
)

const leaderFinalizationPrefix = "LEADER_FINALIZATION_PROOF:"
const leaderVotingStatPrefix = "LEADER_VOTING_STAT:"

func leaderFinalizationKey(chainId, leader string) []byte {
	return []byte(leaderFinalizationPrefix + chainId + ":" + leader)
}

func leaderVotingStatKey(chainId, leader string) []byte {
	return []byte(leaderVotingStatPrefix + chainId + ":" + leader)
}

func StoreLeaderFinalizationProof(proof structures.LeaderFinalizationProofBundle) error {
	payload, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return databases.FINALIZATION_VOTING_STATS.Put(leaderFinalizationKey(proof.ChainId, proof.Leader), payload, nil)
}

func LoadLeaderFinalizationProof(chainId, leader string) (structures.LeaderFinalizationProofBundle, error) {
	var proof structures.LeaderFinalizationProofBundle
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(leaderFinalizationKey(chainId, leader), nil)
	if err != nil {
		if errors.Is(err, ldbErrors.ErrNotFound) {
			return proof, nil
		}
		return proof, err
	}
	if len(raw) == 0 {
		return proof, nil
	}
	if err := json.Unmarshal(raw, &proof); err != nil {
		return proof, err
	}
	return proof, nil
}

func StoreLeaderVotingStat(chainId, leader string, stat structures.VotingStat) error {
	payload, err := json.Marshal(stat)
	if err != nil {
		return err
	}
	return databases.FINALIZATION_VOTING_STATS.Put(leaderVotingStatKey(chainId, leader), payload, nil)
}

func LoadLeaderVotingStat(chainId, leader string) (structures.VotingStat, error) {
	stat := structures.NewVotingStatTemplate()
	raw, err := databases.FINALIZATION_VOTING_STATS.Get(leaderVotingStatKey(chainId, leader), nil)
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
