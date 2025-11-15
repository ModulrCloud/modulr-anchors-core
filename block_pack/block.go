package block_pack

import (
	"sort"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

type Block struct {
	Creator   string            `json:"creator"`
	Time      int64             `json:"time"`
	Epoch     string            `json:"epoch"`
	ExtraData map[string]string `json:"extraData"`
	Index     int               `json:"index"`
	PrevHash  string            `json:"prevHash"`
	Sig       string            `json:"sig"`
}

func formatExtraData(extraData map[string]string) string {
	if len(extraData) == 0 {
		return ""
	}

	keys := make([]string, 0, len(extraData))
	for key := range extraData {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+extraData[key])
	}

	return strings.Join(parts, ",")
}

func NewBlock(extraData map[string]string, epochFullID string, metadata *structures.GenerationThreadMetadataHandler) *Block {
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
