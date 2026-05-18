package threads

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/modulrcloud/modulr-anchors-core/tests/testenv"

	"github.com/modulrcloud/modulr-anchors-core/constants"
	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/gorilla/websocket"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestAlfpCollectionPollsCoreQuorumWhenPodHasNoProof(t *testing.T) {
	resetAlfpCollectionState(t)
	databases.EPOCH_DATA = openAlfpCollectionTempDB(t, "epoch-data")

	anchorKey := cryptography.GenerateKeyPair("", "", nil)
	globals.CONFIGURATION.PublicKey = anchorKey.Pub
	globals.CONFIGURATION.PrivateKey = anchorKey.Prv
	globals.CONFIGURATION.PointOfDistributionWS = startEmptyAlfpPodServer(t)
	globals.CORE_GENESIS.NetworkParameters = structures.CoreNetworkParameters{
		EpochDuration:      10_000,
		LeadershipDuration: 1,
	}

	quorum := []cryptography.Ed25519Box{
		cryptography.GenerateKeyPair("", "", nil),
		cryptography.GenerateKeyPair("", "", nil),
		cryptography.GenerateKeyPair("", "", nil),
	}
	leader := quorum[0].Pub
	epochId := 1
	epochHash := "core-epoch-1"
	epochFullID := epochHash + "#" + strconv.Itoa(epochId)

	var coreQuorumRequests atomic.Int32
	coreValidators := make([]structures.CoreValidatorStorage, 0, len(quorum))
	coreQuorumPubkeys := make([]string, 0, len(quorum))
	for _, validator := range quorum {
		coreQuorumPubkeys = append(coreQuorumPubkeys, validator.Pub)
		coreValidators = append(coreValidators, structures.CoreValidatorStorage{
			Pubkey:          validator.Pub,
			WssValidatorUrl: startCoreValidatorAlfpServer(t, validator, leader, epochFullID, &coreQuorumRequests),
		})
	}
	globals.CORE_GENESIS.Validators = coreValidators

	utils.PersistCoreQuorumState(&structures.CoreQuorumState{LatestEpochId: epochId})
	utils.PersistCoreEpochData(&structures.CoreEpochData{
		EpochId:         epochId,
		EpochHash:       epochHash,
		Quorum:          coreQuorumPubkeys,
		LeadersSequence: []string{leader},
	})
	utils.PersistAggregatedEpochRotationProof(&structures.AggregatedEpochRotationProof{
		EpochId:     0,
		NextEpochId: epochId,
		EpochData: structures.NextEpochData{
			NextEpochHash:               epochHash,
			NextEpochQuorum:             coreQuorumPubkeys,
			NextEpochLeadersSequence:    []string{leader},
			NextEpochStartTimestamp:     1,
			NextEpochValidatorsRegistry: coreQuorumPubkeys,
		},
		EpochDataHash:     "not-used-by-alfp-scheduler",
		FinishedOnHeight:  1,
		FinishedOnHash:    "finished",
		FinishedOnBlockId: "0:leader:0",
		Proofs:            map[string]string{},
	})

	runAlfpCollectionTick()

	if got := coreQuorumRequests.Load(); got != int32(len(quorum)) {
		t.Fatalf("expected anchor to poll all %d core quorum validators, got %d requests", len(quorum), got)
	}
	if !globals.MEMPOOL.HasLeaderFinalizationProof(epochId, leader) {
		t.Fatalf("expected proactively collected ALFP in mempool")
	}

	proofs := globals.MEMPOOL.DrainAggregatedLeaderFinalizationProofs(epochId)
	if len(proofs) != 1 {
		t.Fatalf("expected one collected ALFP, got %d", len(proofs))
	}
	if proofs[0].EpochIndex != epochId || proofs[0].Leader != leader || len(proofs[0].Signatures) != len(quorum) {
		t.Fatalf("unexpected collected ALFP: %+v", proofs[0])
	}
	if !utils.VerifyCoreAlfp(&proofs[0]) {
		t.Fatalf("collected ALFP does not verify against core quorum")
	}
}

func startEmptyAlfpPodServer(t *testing.T) string {
	t.Helper()

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("failed to upgrade PoD websocket: %v", err)
			return
		}
		defer conn.Close()

		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"proof":null}`)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	return httpURLToWS(server.URL)
}

func startCoreValidatorAlfpServer(
	t *testing.T,
	validator cryptography.Ed25519Box,
	leader string,
	epochFullID string,
	requests *atomic.Int32,
) string {
	t.Helper()

	upgrader := websocket.Upgrader{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("failed to upgrade core validator websocket: %v", err)
			return
		}
		defer conn.Close()

		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				return
			}

			var req struct {
				Route                   string                `json:"route"`
				EpochIndex              int                   `json:"epochIndex"`
				IndexOfLeaderToFinalize int                   `json:"indexOfLeaderToFinalize"`
				SkipData                structures.VotingStat `json:"skipData"`
			}
			if err := json.Unmarshal(raw, &req); err != nil {
				t.Errorf("failed to decode core quorum request: %v", err)
				return
			}
			if req.Route != constants.WsRouteGetLeaderFinalizationProof {
				t.Errorf("unexpected core quorum route: %s", req.Route)
				return
			}
			requests.Add(1)

			payload := strings.Join([]string{
				constants.SigningPrefixLeaderFinalization,
				leader,
				strconv.Itoa(req.SkipData.Index),
				req.SkipData.Hash,
				epochFullID,
			}, ":")
			resp := struct {
				Status          string `json:"status"`
				Voter           string `json:"voter"`
				ForLeaderPubkey string `json:"forLeaderPubkey"`
				Sig             string `json:"sig"`
			}{
				Status:          "OK",
				Voter:           validator.Pub,
				ForLeaderPubkey: leader,
				Sig:             cryptography.GenerateSignature(validator.Prv, payload),
			}
			respBytes, err := json.Marshal(resp)
			if err != nil {
				t.Errorf("failed to encode core quorum response: %v", err)
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, respBytes); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)

	return httpURLToWS(server.URL)
}

func resetAlfpCollectionState(t *testing.T) {
	t.Helper()

	alfpCollectionMu.Lock()
	for _, st := range alfpCollectionStates {
		closeEpochCollectionStateLocked(st)
	}
	alfpCollectionStates = make(map[int]*epochCollectionState)
	alfpCollectionInFlight = make(map[string]struct{})
	alfpCollectionMu.Unlock()

	globals.MEMPOOL.ClearEpochProofs(1)
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()
	handlers.APPROVEMENT_THREAD_METADATA.Handler = structures.ApprovementThreadMetadataHandler{}
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

	if websocket_pack.ANCHORS_POD_CONNECTION != nil {
		_ = websocket_pack.ANCHORS_POD_CONNECTION.Close()
		websocket_pack.ANCHORS_POD_CONNECTION = nil
	}
	t.Cleanup(func() {
		if websocket_pack.ANCHORS_POD_CONNECTION != nil {
			_ = websocket_pack.ANCHORS_POD_CONNECTION.Close()
			websocket_pack.ANCHORS_POD_CONNECTION = nil
		}
	})
}

func httpURLToWS(rawURL string) string {
	return "ws" + strings.TrimPrefix(rawURL, "http")
}

func openAlfpCollectionTempDB(t *testing.T, name string) *leveldb.DB {
	t.Helper()

	db, err := leveldb.OpenFile(filepath.Join(t.TempDir(), name), nil)
	if err != nil {
		t.Fatalf("failed to open temp db: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	return db
}
