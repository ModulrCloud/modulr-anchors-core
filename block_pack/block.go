package block_pack

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

type Block struct {
	Creator   string           `json:"creator"`
	Time      int64            `json:"time"`
	Epoch     string           `json:"epoch"`
	ExtraData ExtraDataToBlock `json:"extraData"`
	Index     int              `json:"index"`
	PrevHash  string           `json:"prevHash"`
	Sig       string           `json:"sig"`
}

func NewBlock(extraData ExtraDataToBlock, epochFullID string, metadata *structures.GenerationThreadMetadataHandler) *Block {
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

	jsonedExtraData, err := json.Marshal(block.ExtraData)

	if err != nil {
		panic("GetHash: failed to marshal extraData: " + err.Error())
	}

	dataToHash := strings.Join([]string{
		block.Creator,
		strconv.FormatInt(block.Time, 10),
		globals.GENESIS.NetworkId,
		block.Epoch,
		string(jsonedExtraData),
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
