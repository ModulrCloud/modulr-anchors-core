package block_pack

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

type Block struct {
	Creator   string                    `json:"creator"`
	Time      int64                     `json:"time"`
	Epoch     string                    `json:"epoch"`
	ExtraData structures.BlockExtraData `json:"extraData"`
	Index     int                       `json:"index"`
	PrevHash  string                    `json:"prevHash"`
	Sig       string                    `json:"sig"`
}

func formatExtraData(extraData structures.BlockExtraData) string {
	parts := make([]string, 0)

	if len(extraData.Fields) > 0 {
		keys := make([]string, 0, len(extraData.Fields))
		for key := range extraData.Fields {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			parts = append(parts, key+"="+extraData.Fields[key])
		}
	}

	if len(extraData.RotationProofs) > 0 {
		proofs := make([]structures.AnchorRotationProofBundle, len(extraData.RotationProofs))
		copy(proofs, extraData.RotationProofs)
		sort.Slice(proofs, func(i, j int) bool {
			if proofs[i].EpochIndex != proofs[j].EpochIndex {
				return proofs[i].EpochIndex < proofs[j].EpochIndex
			}
			if proofs[i].Creator != proofs[j].Creator {
				return proofs[i].Creator < proofs[j].Creator
			}
			return proofs[i].VotingStat.Index < proofs[j].VotingStat.Index
		})
		for _, proof := range proofs {
			signers := make([]string, 0, len(proof.Signatures))
			for signer := range proof.Signatures {
				signers = append(signers, signer)
			}
			sort.Strings(signers)
			sigParts := make([]string, 0, len(signers))
			for _, signer := range signers {
				sigParts = append(sigParts, signer+"="+proof.Signatures[signer])
			}
			parts = append(parts, fmt.Sprintf(
				"rotation:%d:%s:%d:%s:%s",
				proof.EpochIndex,
				proof.Creator,
				proof.VotingStat.Index,
				proof.VotingStat.Hash,
				strings.Join(sigParts, "|"),
			))
		}
	}

	if len(extraData.LeaderFinalizationProofs) > 0 {
		proofs := make([]structures.LeaderFinalizationProofBundle, len(extraData.LeaderFinalizationProofs))
		copy(proofs, extraData.LeaderFinalizationProofs)
		sort.Slice(proofs, func(i, j int) bool {
			if proofs[i].ChainId != proofs[j].ChainId {
				return proofs[i].ChainId < proofs[j].ChainId
			}
			if proofs[i].Leader != proofs[j].Leader {
				return proofs[i].Leader < proofs[j].Leader
			}
			return proofs[i].VotingStat.Index < proofs[j].VotingStat.Index
		})
		for _, proof := range proofs {
			signers := make([]string, 0, len(proof.Signatures))
			for signer := range proof.Signatures {
				signers = append(signers, signer)
			}
			sort.Strings(signers)
			sigParts := make([]string, 0, len(signers))
			for _, signer := range signers {
				sigParts = append(sigParts, signer+"="+proof.Signatures[signer])
			}
			parts = append(parts, fmt.Sprintf(
				"leader_finalization:%s:%s:%d:%s:%s",
				proof.ChainId,
				proof.Leader,
				proof.VotingStat.Index,
				proof.VotingStat.Hash,
				strings.Join(sigParts, "|"),
			))
		}
	}

	return strings.Join(parts, ",")
}

func NewBlock(extraData structures.BlockExtraData, epochFullID string, metadata *structures.GenerationThreadMetadataHandler) *Block {
	return &Block{
		Creator:   globals.CONFIGURATION.PublicKey,
		Time:      utils.GetUTCTimestampInMilliSeconds(),
		Epoch:     epochFullID,
		ExtraData: extraData,
		Index:     metadata.NextIndex,
		PrevHash:  metadata.PrevHash,
		Sig:       "",
	}
}

func (block *Block) GetHash() string {

	dataToHash := strings.Join([]string{
		block.Creator,
		strconv.FormatInt(block.Time, 10),
		globals.GENESIS.NetworkId,
		block.Epoch,
		formatExtraData(block.ExtraData),
		strconv.Itoa(block.Index),
		block.PrevHash,
	}, ":")

	return utils.Blake3(dataToHash)
}

func (block *Block) SignBlock() {

	block.Sig = cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, block.GetHash())

}

func (block *Block) VerifySignature() bool {

	return cryptography.VerifySignature(block.GetHash(), block.Creator, block.Sig)

}
