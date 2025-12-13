package threads

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

var httpClient = &http.Client{Timeout: 5 * time.Second}

func AnchorRotationCollectorThread() {

	ticker := time.NewTicker(5 * time.Second)

	defer ticker.Stop()

	for range ticker.C {

		collectRotationProofs()

	}

}

func collectRotationProofs() {

	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RLock()
	epochHandlers := handlers.APPROVEMENT_THREAD_METADATA.Handler.GetEpochHandlers()
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.RUnlock()

	totalEpochs := len(epochHandlers)
	totalCreators := 0
	rotationCandidates := 0
	proofsCollected := 0

	for idx := range epochHandlers {
		creators, candidates, proofs := handleEpochForRotation(&epochHandlers[idx])
		totalCreators += creators
		rotationCandidates += candidates
		proofsCollected += proofs
	}

	summaryColor := utils.GREEN_COLOR
	metrics := []string{
		utils.ColoredMetric("Epochs", totalEpochs, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Total_creators", totalCreators, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Rotation_candidates", rotationCandidates, utils.CYAN_COLOR, summaryColor),
		utils.ColoredMetric("Proofs_collected", proofsCollected, utils.CYAN_COLOR, summaryColor),
	}
	utils.LogWithTime(
		fmt.Sprintf("Anchor rotation: Iteration summary %s", strings.Join(metrics, " ")),
		summaryColor,
	)
}

func handleEpochForRotation(epochHandler *structures.EpochDataHandler) (int, int, int) {
	if len(epochHandler.AnchorsRegistry) == 0 {
		return 0, 0, 0
	}
	rotationCandidates := 0
	proofsCollected := 0
	for _, creator := range epochHandler.AnchorsRegistry {
		candidate, proof := processAnchorRotation(epochHandler, creator)
		if candidate {
			rotationCandidates++
		}
		if proof {
			proofsCollected++
		}
	}
	return len(epochHandler.AnchorsRegistry), rotationCandidates, proofsCollected
}

func processAnchorRotation(epochHandler *structures.EpochDataHandler, anchorPubkey string) (bool, bool) {
	if !utils.IsFinalizationProofsDisabled(epochHandler.Id, anchorPubkey) {
		return false, false
	}
	if utils.HasAggregatedAnchorRotationProof(epochHandler.Id, anchorPubkey) {
		return false, false
	}

	mutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(epochHandler.Id, anchorPubkey)
	mutex.Lock()
	defer mutex.Unlock()

	if !utils.IsFinalizationProofsDisabled(epochHandler.Id, anchorPubkey) || utils.HasAggregatedAnchorRotationProof(epochHandler.Id, anchorPubkey) {
		return false, false
	}

	localVotingStat, err := utils.ReadVotingStat(epochHandler.Id, anchorPubkey)
	if err != nil {
		utils.LogWithTime(fmt.Sprintf("Anchor rotation: failed to read voting stat for %s in epoch %d: %v", anchorPubkey, epochHandler.Id, err), utils.YELLOW_COLOR)
		return true, false
	}

	signatures := collectRotationSignatures(epochHandler, anchorPubkey, localVotingStat)
	majority := utils.GetQuorumMajority(epochHandler)
	if len(signatures) < majority {
		return true, false
	}

	proof := structures.AggregatedAnchorRotationProof{
		EpochIndex: epochHandler.Id,
		Anchor:     anchorPubkey,
		VotingStat: localVotingStat,
		Signatures: signatures,
	}
	if err := utils.StoreAggregatedAnchorRotationProof(proof); err != nil {
		utils.LogWithTime(fmt.Sprintf("Anchor rotation: failed to persist proof for %s epoch %d: %v", anchorPubkey, epochHandler.Id, err), utils.YELLOW_COLOR)
		return true, false
	}
	globals.MEMPOOL.AddAggregatedAnchorRotationProof(proof)
	broadcastAggregatedAnchorRotationProof(epochHandler, proof)
	utils.LogWithTime(fmt.Sprintf("Anchor rotation: collected %d signatures for %s in epoch %d", len(signatures), anchorPubkey, epochHandler.Id), utils.GREEN_COLOR)
	return true, true
}

func collectRotationSignatures(epochHandler *structures.EpochDataHandler, anchorPubkey string, localVotingStat structures.VotingStat) map[string]string {
	quorumMembers := utils.GetQuorumUrlsAndPubkeys(epochHandler)
	payload := structures.AnchorRotationProofRequest{EpochIndex: epochHandler.Id, ForAnchor: anchorPubkey, Proposal: localVotingStat}
	requestBody, _ := json.Marshal(payload)
	signatures := make(map[string]string)
	majority := utils.GetQuorumMajority(epochHandler)

	dataThatShouldBeSigned := utils.BuildAnchorRotationProofPayload(anchorPubkey, localVotingStat.Index, localVotingStat.Hash, epochHandler.Id)

	type rotationResult struct {
		pubKey     string
		signature  string
		votingStat *structures.VotingStat
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results := make(chan rotationResult, len(quorumMembers))
	wg := &sync.WaitGroup{}

	for _, member := range quorumMembers {
		if member.PubKey == globals.CONFIGURATION.PublicKey || member.Url == "" {
			continue
		}

		wg.Add(1)
		go func(member utils.QuorumMemberData) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				return
			default:
			}

			endpoint := strings.TrimRight(member.Url, "/") + "/request_anchor_rotation_proof"

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestBody))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := httpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			var response structures.AnchorRotationProofResponse
			if err := json.Unmarshal(body, &response); err != nil {
				return
			}

			switch response.Status {
			case "UPGRADE":
				if response.VotingStat != nil {
					parts := strings.Split(response.VotingStat.Afp.BlockId, ":")
					if len(parts) == 3 {
						if indexOfBlockInAfp, err := strconv.Atoi(parts[2]); err == nil {
							proposalHasBiggerIndex := indexOfBlockInAfp >= localVotingStat.Index
							sameHashes := response.VotingStat.Hash == response.VotingStat.Afp.BlockHash
							if proposalHasBiggerIndex && sameHashes && utils.VerifyAggregatedFinalizationProof(&response.VotingStat.Afp, epochHandler) {
								results <- rotationResult{votingStat: response.VotingStat}
								return
							}
						}
					}
				}
			case "OK":
				if response.Signature != "" && resp.StatusCode == http.StatusOK && cryptography.VerifySignature(dataThatShouldBeSigned, member.PubKey, response.Signature) {
					results <- rotationResult{pubKey: member.PubKey, signature: response.Signature}
				}
			}
		}(member)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	hasReachedTarget := false

	for result := range results {
		if result.votingStat != nil {
			cancel()
			if err := utils.StoreVotingStat(epochHandler.Id, anchorPubkey, *result.votingStat); err != nil {
				utils.LogWithTime(fmt.Sprintf("Anchor rotation: failed to store upgraded stat for %s epoch %d: %v", anchorPubkey, epochHandler.Id, err), utils.YELLOW_COLOR)
			}
			return nil
		}

		if result.signature != "" && !hasReachedTarget {
			signatures[result.pubKey] = result.signature
			if len(signatures) >= majority {
				hasReachedTarget = true
				cancel()
			}
		}
	}

	return signatures
}

func postJSON(url string, payload []byte) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func broadcastAggregatedAnchorRotationProof(epochHandler *structures.EpochDataHandler, proof structures.AggregatedAnchorRotationProof) {
	payload := structures.AcceptAggregatedAnchorRotationProofRequest{AggregatedRotationProofs: []structures.AggregatedAnchorRotationProof{proof}}
	body, _ := json.Marshal(payload)
	for _, member := range utils.GetQuorumUrlsAndPubkeys(epochHandler) {
		if member.PubKey == globals.CONFIGURATION.PublicKey || member.Url == "" {
			continue
		}
		endpoint := strings.TrimRight(member.Url, "/") + "/accept_aggregated_anchor_rotation_proof"
		if _, _, err := postJSON(endpoint, body); err != nil {
			utils.LogWithTime(fmt.Sprintf("Anchor rotation: failed to broadcast proof to %s: %v", member.PubKey, err), utils.YELLOW_COLOR)
		}
	}
}
