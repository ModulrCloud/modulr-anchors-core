package websocket_pack

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/lxzan/gws"
)

func GetFinalizationProof(parsedRequest WsFinalizationProofRequest, connection *gws.Conn) {

	if !globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Load() {
		return
	}

	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()

	defer handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	reqEpochID := parsedRequest.Block.Epoch
	epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()

	var epochHandler *structures.EpochDataHandler

	for idx := range epochHandlers {
		candidate := epochHandlers[idx]
		fullID := candidate.Hash + "#" + strconv.Itoa(candidate.Id)
		if fullID == reqEpochID {
			epochHandler = &epochHandlers[idx]
			break
		}
	}
	if epochHandler == nil {
		return
	}

	if !slices.Contains(epochHandler.AnchorsRegistry, parsedRequest.Block.Creator) {
		return
	}

	epochIndex := epochHandler.Id

	creatorMutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(epochIndex, parsedRequest.Block.Creator)

	creatorMutex.Lock()
	defer creatorMutex.Unlock()

	if utils.IsFinalizationProofsDisabled(epochIndex, parsedRequest.Block.Creator) {
		return
	}

	epochIndexStr := strconv.Itoa(epochIndex)

	epochFullID := epochHandler.Hash + "#" + epochIndexStr

	localVotingDataForLeader := structures.NewVotingStatTemplate()

	localVotingDataRaw, err := databases.FINALIZATION_VOTING_STATS.Get([]byte(epochIndexStr+":"+parsedRequest.Block.Creator), nil)

	if err == nil {

		json.Unmarshal(localVotingDataRaw, &localVotingDataForLeader)

	}

	proposedBlockHash := parsedRequest.Block.GetHash()

	itsSameChainSegment := localVotingDataForLeader.Index < int(parsedRequest.Block.Index) || localVotingDataForLeader.Index == int(parsedRequest.Block.Index) && proposedBlockHash == localVotingDataForLeader.Hash && parsedRequest.Block.Epoch == epochFullID

	if itsSameChainSegment {

		proposedBlockId := epochIndexStr + ":" + parsedRequest.Block.Creator + ":" + strconv.Itoa(int(parsedRequest.Block.Index))

		previousBlockIndex := int(parsedRequest.Block.Index - 1)

		var futureVotingDataToStore structures.VotingStat

		if parsedRequest.Block.VerifySignature() && !utils.SignalAboutEpochRotationExists(epochIndex) {

			if localVotingDataForLeader.Index == int(parsedRequest.Block.Index) {

				futureVotingDataToStore = localVotingDataForLeader

			} else {

				futureVotingDataToStore = structures.VotingStat{

					Index: previousBlockIndex,

					Hash: parsedRequest.PreviousBlockAfp.BlockHash,

					Afp: parsedRequest.PreviousBlockAfp,
				}

			}

			previousBlockId := epochIndexStr + ":" + parsedRequest.Block.Creator + ":" + strconv.Itoa(previousBlockIndex)

			// Check if AFP inside related to previous block AFP

			if parsedRequest.Block.Index == 0 || previousBlockId == parsedRequest.PreviousBlockAfp.BlockId && utils.VerifyAggregatedFinalizationProof(&parsedRequest.PreviousBlockAfp, epochHandler) {

				// Store the block and return finalization proof

				blockBytes, err := json.Marshal(parsedRequest.Block)

				if err == nil {

					// 1. Store the block

					err = databases.BLOCKS.Put([]byte(proposedBlockId), blockBytes, nil)

					if err == nil {

						processAnchorRotationProofsAsync(parsedRequest.Block, epochHandler, proposedBlockId)

						afpBytes, err := json.Marshal(parsedRequest.PreviousBlockAfp)

						if err == nil {

							// 2. Store the AFP for previous block

							errStoreAfp := databases.EPOCH_DATA.Put([]byte("AFP:"+parsedRequest.PreviousBlockAfp.BlockId), afpBytes, nil)

							if errStoreAfp == nil {

								// 3. Store the voting stats

								if errStoreVotingStats := utils.StoreVotingStat(epochIndex, parsedRequest.Block.Creator, futureVotingDataToStore); errStoreVotingStats == nil {

									// Only after we stored the these 3 components = generate signature (finalization proof)

									dataToSign, prevBlockHash := "", ""

									if parsedRequest.Block.Index == 0 {

										prevBlockHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

									} else {

										prevBlockHash = parsedRequest.PreviousBlockAfp.BlockHash

									}

									dataToSign += strings.Join([]string{prevBlockHash, proposedBlockId, proposedBlockHash, epochIndexStr}, ":")

									response := WsFinalizationProofResponse{
										Voter:             globals.CONFIGURATION.PublicKey,
										FinalizationProof: cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, dataToSign),
										VotedForHash:      proposedBlockHash,
									}

									jsonResponse, err := json.Marshal(response)

									if err == nil {

										go SendBlockAndAfpToAnchorsPoD(parsedRequest.Block, &parsedRequest.PreviousBlockAfp)

										connection.WriteMessage(gws.OpcodeText, jsonResponse)

									}

								}

							}

						}

					}

				}

			}

		}

	}

}

func GetBlockWithAggregatedFinalizationProof(parsedRequest WsBlockWithAfpRequest, connection *gws.Conn) {

	if blockBytes, err := databases.BLOCKS.Get([]byte(parsedRequest.BlockId), nil); err == nil {

		var block block_pack.Block

		if err := json.Unmarshal(blockBytes, &block); err == nil {

			resp := WsBlockWithAfpResponse{&block, nil}

			// Now try to get AFP for block

			parts := strings.Split(parsedRequest.BlockId, ":")

			if len(parts) > 0 {

				last := parts[len(parts)-1]

				if idx, err := strconv.ParseUint(last, 10, 64); err == nil {

					parts[len(parts)-1] = strconv.FormatUint(idx+1, 10)

					nextBlockId := strings.Join(parts, ":")

					// Remark: To make sure block with index X is 100% approved we need to get the AFP for next block

					if afpBytes, err := databases.EPOCH_DATA.Get([]byte("AFP:"+nextBlockId), nil); err == nil {

						var afp structures.AggregatedFinalizationProof

						if err := json.Unmarshal(afpBytes, &afp); err == nil {

							resp.Afp = &afp

						}

					}

				}

			}

			jsonResponse, err := json.Marshal(resp)

			if err == nil {

				connection.WriteMessage(gws.OpcodeText, jsonResponse)

			}

		}

	}

}

func GetVotingStat(parsedRequest WsVotingStatRequest, connection *gws.Conn) {

	if !globals.FLOOD_PREVENTION_FLAG_FOR_ROUTES.Load() {
		return
	}

	epochHandler := utils.GetEpochHandlerByID(parsedRequest.EpochIndex)
	if epochHandler == nil {
		resp := WsVotingStatResponse{
			Status:     "ERROR",
			EpochIndex: parsedRequest.EpochIndex,
			Creator:    parsedRequest.Creator,
			VotingStat: structures.NewVotingStatTemplate(),
			Error:      "unknown_epoch",
		}
		if b, err := json.Marshal(resp); err == nil {
			connection.WriteMessage(gws.OpcodeText, b)
		}
		return
	}

	if parsedRequest.Creator == "" || !slices.Contains(epochHandler.AnchorsRegistry, parsedRequest.Creator) {
		resp := WsVotingStatResponse{
			Status:     "ERROR",
			EpochIndex: parsedRequest.EpochIndex,
			Creator:    parsedRequest.Creator,
			VotingStat: structures.NewVotingStatTemplate(),
			Error:      "unknown_creator",
		}
		if b, err := json.Marshal(resp); err == nil {
			connection.WriteMessage(gws.OpcodeText, b)
		}
		return
	}

	stat, err := utils.ReadVotingStat(parsedRequest.EpochIndex, parsedRequest.Creator)
	if err != nil {
		resp := WsVotingStatResponse{
			Status:     "ERROR",
			EpochIndex: parsedRequest.EpochIndex,
			Creator:    parsedRequest.Creator,
			VotingStat: structures.NewVotingStatTemplate(),
			Error:      "read_failed",
		}
		if b, mErr := json.Marshal(resp); mErr == nil {
			connection.WriteMessage(gws.OpcodeText, b)
		}
		return
	}

	resp := WsVotingStatResponse{
		Status:     "OK",
		EpochIndex: parsedRequest.EpochIndex,
		Creator:    parsedRequest.Creator,
		VotingStat: stat,
	}
	if b, err := json.Marshal(resp); err == nil {
		connection.WriteMessage(gws.OpcodeText, b)
	}
}

func processAnchorRotationProofsAsync(block block_pack.Block, epochHandler *structures.EpochDataHandler, blockId string) {

	if len(block.ExtraData.AggregatedAnchorRotationProofs) == 0 || epochHandler == nil {
		return
	}

	go func() {
		for _, proof := range block.ExtraData.AggregatedAnchorRotationProofs {
			if err := utils.VerifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
				continue
			}
			// Trigger #2: if we observed a valid AARP targeting this anchor in any block,
			// stop sending any proofs to that receiver anchor.
			utils.MarkAnchorDisabledByAarp(proof.EpochIndex, proof.Anchor)
			if err := utils.StoreAggregatedAnchorRotationProofPresence(proof.EpochIndex, block.Creator, proof.Anchor, blockId); err != nil {
				continue
			}
		}
	}()
}
