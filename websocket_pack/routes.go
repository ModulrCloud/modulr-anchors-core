package websocket_pack

import (
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/block_pack"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/lxzan/gws"
)

func getCreatorMutex(epochIndex int, creator string, anchorsRegistry []string) (*sync.Mutex, bool) {
	allowed := false
	for _, anchor := range anchorsRegistry {
		if anchor == creator {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, false
	}
	return utils.GetBlockCreatorMutex(epochIndex, creator), true
}

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

	epochIndex := epochHandler.Id

	creatorMutex, allowed := getCreatorMutex(epochIndex, parsedRequest.Block.Creator, epochHandler.AnchorsRegistry)

	if !allowed {
		return
	}

	epochFullID := epochHandler.Hash + "#" + strconv.Itoa(epochIndex)

	if utils.IsFinalizationProofsDisabled(epochIndex, parsedRequest.Block.Creator) {
		return
	}

	localVotingDataForLeader := structures.NewVotingStatTemplate()

	localVotingDataRaw, err := databases.FINALIZATION_VOTING_STATS.Get([]byte(strconv.Itoa(epochIndex)+":"+parsedRequest.Block.Creator), nil)

	if err == nil {

		json.Unmarshal(localVotingDataRaw, &localVotingDataForLeader)

	}

	proposedBlockHash := parsedRequest.Block.GetHash()

	itsSameChainSegment := localVotingDataForLeader.Index < int(parsedRequest.Block.Index) || localVotingDataForLeader.Index == int(parsedRequest.Block.Index) && proposedBlockHash == localVotingDataForLeader.Hash && parsedRequest.Block.Epoch == epochFullID

	if itsSameChainSegment {

		proposedBlockId := strconv.Itoa(epochIndex) + ":" + parsedRequest.Block.Creator + ":" + strconv.Itoa(int(parsedRequest.Block.Index))

		previousBlockIndex := int(parsedRequest.Block.Index - 1)

		var futureVotingDataToStore structures.VotingStat

		if parsedRequest.Block.VerifySignature() && !utils.SignalAboutEpochRotationExists(epochIndex) {

			creatorMutex.Lock()

			defer creatorMutex.Unlock()

			if localVotingDataForLeader.Index == int(parsedRequest.Block.Index) {

				futureVotingDataToStore = localVotingDataForLeader

			} else {

				futureVotingDataToStore = structures.VotingStat{

					Index: previousBlockIndex,

					Hash: parsedRequest.PreviousBlockAfp.BlockHash,

					Afp: parsedRequest.PreviousBlockAfp,
				}

			}

			previousBlockId := strconv.Itoa(epochIndex) + ":" + parsedRequest.Block.Creator + ":" + strconv.Itoa(previousBlockIndex)

			// Check if AFP inside related to previous block AFP

			if parsedRequest.Block.Index == 0 || previousBlockId == parsedRequest.PreviousBlockAfp.BlockId && utils.VerifyAggregatedFinalizationProof(&parsedRequest.PreviousBlockAfp, epochHandler) {

				// Store the block and return finalization proof

				blockBytes, err := json.Marshal(parsedRequest.Block)

				if err == nil {

					// 1. Store the block

					err = databases.BLOCKS.Put([]byte(proposedBlockId), blockBytes, nil)

					if err == nil {

						afpBytes, err := json.Marshal(parsedRequest.PreviousBlockAfp)

						if err == nil {

							// 2. Store the AFP for previous block

							errStore := databases.EPOCH_DATA.Put([]byte("AFP:"+parsedRequest.PreviousBlockAfp.BlockId), afpBytes, nil)

							votingStatBytes, errParse := json.Marshal(futureVotingDataToStore)

							if errStore == nil && errParse == nil {

								// 3. Store the voting stats

								err := databases.FINALIZATION_VOTING_STATS.Put([]byte(strconv.Itoa(epochIndex)+":"+parsedRequest.Block.Creator), votingStatBytes, nil)

								if err == nil {

									// Only after we stored the these 3 components = generate signature (finalization proof)

									dataToSign, prevBlockHash := "", ""

									if parsedRequest.Block.Index == 0 {

										prevBlockHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

									} else {

										prevBlockHash = parsedRequest.PreviousBlockAfp.BlockHash

									}

									dataToSign += strings.Join([]string{prevBlockHash, proposedBlockId, proposedBlockHash, epochFullID}, ":")

									response := WsFinalizationProofResponse{
										Voter:             globals.CONFIGURATION.PublicKey,
										FinalizationProof: cryptography.GenerateSignature(globals.CONFIGURATION.PrivateKey, dataToSign),
										VotedForHash:      proposedBlockHash,
									}

									jsonResponse, err := json.Marshal(response)

									if err == nil {

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
