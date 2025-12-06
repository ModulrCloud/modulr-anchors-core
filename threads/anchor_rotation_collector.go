package threads

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
		candidate, proof := processCreatorRotation(epochHandler, creator)
		if candidate {
			rotationCandidates++
		}
		if proof {
			proofsCollected++
		}
	}
	return len(epochHandler.AnchorsRegistry), rotationCandidates, proofsCollected
}

func processCreatorRotation(epochHandler *structures.EpochDataHandler, creator string) (bool, bool) {
	if !utils.IsFinalizationProofsDisabled(epochHandler.Id, creator) {
		return false, false
	}
	if utils.HasAggregatedAnchorRotationProof(epochHandler.Id, creator) {
		return false, false
	}

	mutex := globals.BLOCK_CREATORS_MUTEX_REGISTRY.GetMutex(epochHandler.Id, creator)
	mutex.Lock()
	defer mutex.Unlock()

	if !utils.IsFinalizationProofsDisabled(epochHandler.Id, creator) || utils.HasAggregatedAnchorRotationProof(epochHandler.Id, creator) {
		return false, false
	}

	stat, err := utils.ReadVotingStat(epochHandler.Id, creator)
	if err != nil {
		utils.LogWithTime(fmt.Sprintf("anchor rotation: failed to read voting stat for %s in epoch %d: %v", creator, epochHandler.Id, err), utils.YELLOW_COLOR)
		return true, false
	}
	if stat.Index < 0 || stat.Hash == "" {
		return true, false
	}

	signatures := collectRotationSignatures(epochHandler, creator, stat)
	majority := utils.GetQuorumMajority(epochHandler)
	if len(signatures) < majority {
		return true, false
	}

	proof := structures.AggregatedAnchorRotationProof{
		EpochIndex: epochHandler.Id,
		Anchor:     creator,
		VotingStat: stat,
		Signatures: signatures,
	}
	if err := utils.StoreAggregatedAnchorRotationProof(proof); err != nil {
		utils.LogWithTime(fmt.Sprintf("anchor rotation: failed to persist proof for %s epoch %d: %v", creator, epochHandler.Id, err), utils.YELLOW_COLOR)
		return true, false
	}
	globals.MEMPOOL.AddAggregatedAnchorRotationProof(proof)
	broadcastRotationProof(epochHandler, proof)
	utils.LogWithTime(fmt.Sprintf("anchor rotation: collected %d signatures for %s in epoch %d", len(signatures), creator, epochHandler.Id), utils.GREEN_COLOR)
	return true, true
}

func collectRotationSignatures(epochHandler *structures.EpochDataHandler, creator string, stat structures.VotingStat) map[string]string {
	quorumMembers := utils.GetQuorumUrlsAndPubkeys(epochHandler)
	payload := structures.AnchorRotationProofRequest{EpochIndex: epochHandler.Id, Creator: creator, Proposal: stat}
	requestBody, _ := json.Marshal(payload)
	signatures := make(map[string]string)
	majority := utils.GetQuorumMajority(epochHandler)

	for _, member := range quorumMembers {
		if member.PubKey == globals.CONFIGURATION.PublicKey || member.Url == "" {
			continue
		}
		endpoint := strings.TrimRight(member.Url, "/") + "/request_anchor_rotation_proof"
		body, status, err := postJSON(endpoint, requestBody)
		if err != nil {
			continue
		}
		var response structures.AnchorRotationProofResponse
		if err := json.Unmarshal(body, &response); err != nil {
			continue
		}
		switch response.Status {
		case "UPGRADE":
			if response.VotingStat != nil {
				if err := utils.StoreVotingStat(epochHandler.Id, creator, *response.VotingStat); err != nil {
					utils.LogWithTime(fmt.Sprintf("anchor rotation: failed to store upgraded stat for %s epoch %d: %v", creator, epochHandler.Id, err), utils.YELLOW_COLOR)
				}
				return nil
			}
		case "OK":
			if response.VotingStat == nil {
				continue
			}
			if response.VotingStat.Index > stat.Index || !strings.EqualFold(response.VotingStat.Hash, stat.Hash) {
				if err := utils.StoreVotingStat(epochHandler.Id, creator, *response.VotingStat); err != nil {
					utils.LogWithTime(fmt.Sprintf("anchor rotation: failed to store fresher stat for %s epoch %d: %v", creator, epochHandler.Id, err), utils.YELLOW_COLOR)
				}
				return nil
			}
			if response.Signature != "" && status == http.StatusOK {
				signatures[member.PubKey] = response.Signature
			}
		}
		if len(signatures) >= majority {
			break
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

func broadcastRotationProof(epochHandler *structures.EpochDataHandler, proof structures.AggregatedAnchorRotationProof) {
	payload := structures.AcceptAggregatedAnchorRotationProofRequest{AggregatedRotationProofs: []structures.AggregatedAnchorRotationProof{proof}}
	body, _ := json.Marshal(payload)
	for _, member := range utils.GetQuorumUrlsAndPubkeys(epochHandler) {
		if member.PubKey == globals.CONFIGURATION.PublicKey || member.Url == "" {
			continue
		}
		endpoint := strings.TrimRight(member.Url, "/") + "/accept_aggregated_anchor_rotation_proof"
		if _, _, err := postJSON(endpoint, body); err != nil {
			utils.LogWithTime(fmt.Sprintf("anchor rotation: failed to broadcast proof to %s: %v", member.PubKey, err), utils.YELLOW_COLOR)
		}
	}
}
