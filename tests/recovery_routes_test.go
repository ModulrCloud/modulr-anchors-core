package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	_ "github.com/modulrcloud/modulr-anchors-core/tests/testenv"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/http_pack/routes"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/utils"
	"github.com/modulrcloud/modulr-anchors-core/websocket_pack"

	"github.com/fasthttp/router"
	"github.com/gorilla/websocket"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/valyala/fasthttp"
)

func TestRecoveryCoreQuorumRoutes(t *testing.T) {
	configureRecoverySigningKey(t)
	databases.EPOCH_DATA = openTempDB(t, "epoch-data")

	coreValidator := cryptography.GenerateKeyPair("", "", nil)
	nextValidator := structures.CoreValidatorStorage{
		Pubkey:          coreValidator.Pub,
		ValidatorUrl:    "http://core-validator",
		WssValidatorUrl: "ws://core-validator",
	}
	globals.CORE_GENESIS = structures.CoreGenesis{
		Validators: []structures.CoreValidatorStorage{nextValidator},
	}
	utils.ResetCoreValidatorEndpointCacheForTest()

	t.Run("latest returns 404 before core quorum state is initialized", func(t *testing.T) {
		ctx := callRecoveryRoute("/recovery/latest_core_quorum", func(r *router.Router) {
			r.GET("/recovery/latest_core_quorum", routes.GetRecoveryLatestCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "Core quorum state not initialized")
	})

	utils.PersistCoreQuorumState(&structures.CoreQuorumState{LatestEpochId: 0})
	utils.PersistCoreEpochData(&structures.CoreEpochData{
		EpochId:         0,
		EpochHash:       "epoch-0-hash",
		Quorum:          []string{coreValidator.Pub},
		LeadersSequence: []string{coreValidator.Pub},
	})

	t.Run("latest returns 404 while still in genesis epoch", func(t *testing.T) {
		ctx := callRecoveryRoute("/recovery/latest_core_quorum", func(r *router.Router) {
			r.GET("/recovery/latest_core_quorum", routes.GetRecoveryLatestCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "No epoch rotation proof yet (still in genesis epoch)")
	})

	proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{coreValidator})
	utils.PersistAggregatedEpochRotationProof(proof)

	t.Run("specific epoch catches up from local proof and returns signed payload", func(t *testing.T) {
		ctx := callRecoveryRoute("/recovery/core_quorum/1", func(r *router.Router) {
			r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
		})

		assertSignedRecoveryCoreQuorum(t, ctx, proof, "memory_catchup", 0)
	})

	t.Run("latest returns signed cached recovery view", func(t *testing.T) {
		ctx := callRecoveryRoute("/recovery/latest_core_quorum", func(r *router.Router) {
			r.GET("/recovery/latest_core_quorum", routes.GetRecoveryLatestCoreQuorum)
		})

		assertSignedRecoveryCoreQuorum(t, ctx, proof, "memory_catchup", 0)
	})

	t.Run("specific missing epoch returns 404", func(t *testing.T) {
		ctx := callRecoveryRoute("/recovery/core_quorum/2", func(r *router.Router) {
			r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "No epoch rotation proof found for this epoch")
	})
}

func TestRecoveryCoreQuorumRejectsInvalidEpochParameter(t *testing.T) {
	ctx := callRecoveryRoute("/recovery/core_quorum/not-a-number", func(r *router.Router) {
		r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
	})

	assertJSONError(t, ctx, fasthttp.StatusBadRequest, "Invalid epoch parameter")
}

func TestRecoveryCoreQuorumCatchesUpFromPoD(t *testing.T) {
	configureRecoverySigningKey(t)
	routes.ResetRecoveryCoreQuorumViewForTest()
	closeAnchorsPoDConnectionForRecoveryTest(t)
	databases.EPOCH_DATA = openTempDB(t, "epoch-data")

	coreValidator := cryptography.GenerateKeyPair("", "", nil)
	nextValidator := structures.CoreValidatorStorage{
		Pubkey:          coreValidator.Pub,
		ValidatorUrl:    "http://core-validator",
		WssValidatorUrl: "ws://core-validator",
	}
	globals.CORE_GENESIS = structures.CoreGenesis{
		Validators: []structures.CoreValidatorStorage{nextValidator},
	}
	utils.ResetCoreValidatorEndpointCacheForTest()

	utils.PersistCoreQuorumState(&structures.CoreQuorumState{LatestEpochId: 0})
	utils.PersistCoreEpochData(&structures.CoreEpochData{
		EpochId:         0,
		EpochHash:       "epoch-0-hash",
		Quorum:          []string{coreValidator.Pub},
		LeadersSequence: []string{coreValidator.Pub},
	})
	proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{coreValidator})
	globals.CONFIGURATION.PointOfDistributionWS = startEpochRotationProofPoDServer(t, proof)

	ctx := callRecoveryRoute("/recovery/latest_core_quorum", func(r *router.Router) {
		r.GET("/recovery/latest_core_quorum", routes.GetRecoveryLatestCoreQuorum)
	})

	assertSignedRecoveryCoreQuorum(t, ctx, proof, "memory_catchup", 0)
}

func TestRecoveryCoreQuorumCatchesUpFromPeerAnchorHTTP(t *testing.T) {
	localAnchor := cryptography.GenerateKeyPair("", "", nil)
	globals.CONFIGURATION.PublicKey = localAnchor.Pub
	globals.CONFIGURATION.PrivateKey = localAnchor.Prv
	routes.ResetRecoveryCoreQuorumViewForTest()
	closeAnchorsPoDConnectionForRecoveryTest(t)
	databases.EPOCH_DATA = openTempDB(t, "epoch-data")
	databases.APPROVEMENT_THREAD_METADATA = openTempDB(t, "approvement-thread-metadata")

	coreValidator := cryptography.GenerateKeyPair("", "", nil)
	nextValidator := structures.CoreValidatorStorage{
		Pubkey:          coreValidator.Pub,
		ValidatorUrl:    "http://core-validator",
		WssValidatorUrl: "ws://core-validator",
	}
	globals.CORE_GENESIS = structures.CoreGenesis{
		Validators: []structures.CoreValidatorStorage{nextValidator},
	}
	utils.ResetCoreValidatorEndpointCacheForTest()

	utils.PersistCoreQuorumState(&structures.CoreQuorumState{LatestEpochId: 0})
	utils.PersistCoreEpochData(&structures.CoreEpochData{
		EpochId:         0,
		EpochHash:       "epoch-0-hash",
		Quorum:          []string{coreValidator.Pub},
		LeadersSequence: []string{coreValidator.Pub},
	})
	proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{coreValidator})

	peerAnchor := cryptography.GenerateKeyPair("", "", nil)
	peerAnchorURL := startPeerRecoveryAnchorServer(t, peerAnchor, proof)
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()
	handlers.APPROVEMENT_THREAD_METADATA.Handler = structures.ApprovementThreadMetadataHandler{
		EpochDataHandler: structures.EpochDataHandler{
			Id:              0,
			Hash:            "anchor-epoch-0",
			AnchorsRegistry: []string{localAnchor.Pub, peerAnchor.Pub},
			Quorum:          []string{localAnchor.Pub, peerAnchor.Pub},
		},
	}
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()
	writeAnchorStorageToApprovementDB(t, structures.AnchorStorage{
		Pubkey:    peerAnchor.Pub,
		AnchorUrl: peerAnchorURL,
	})
	globals.CONFIGURATION.PointOfDistributionWS = startEmptyAlfpPodServer(t)

	ctx := callRecoveryRoute("/recovery/latest_core_quorum", func(r *router.Router) {
		r.GET("/recovery/latest_core_quorum", routes.GetRecoveryLatestCoreQuorum)
	})

	assertSignedRecoveryCoreQuorum(t, ctx, proof, "memory_catchup", 0)
}

func TestRecoveryCoreQuorumRejectsInvalidExternalCatchUpProofs(t *testing.T) {
	t.Run("PoD proof with tampered epoch data hash is rejected", func(t *testing.T) {
		configureRecoverySigningKey(t)
		routes.ResetRecoveryCoreQuorumViewForTest()
		closeAnchorsPoDConnectionForRecoveryTest(t)
		databases.EPOCH_DATA = openTempDB(t, "epoch-data")

		coreValidator := cryptography.GenerateKeyPair("", "", nil)
		setupRecoveryCoreGenesisAndLocalEpoch(t, coreValidator)
		proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{coreValidator})
		proof.EpochDataHash = "tampered-epoch-data-hash"
		globals.CONFIGURATION.PointOfDistributionWS = startEpochRotationProofPoDServer(t, proof)

		ctx := callRecoveryRoute("/recovery/core_quorum/1", func(r *router.Router) {
			r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "No epoch rotation proof found for this epoch")
	})

	t.Run("PoD proof signed outside current core quorum is rejected", func(t *testing.T) {
		configureRecoverySigningKey(t)
		routes.ResetRecoveryCoreQuorumViewForTest()
		closeAnchorsPoDConnectionForRecoveryTest(t)
		databases.EPOCH_DATA = openTempDB(t, "epoch-data")

		coreValidator := cryptography.GenerateKeyPair("", "", nil)
		nonQuorumValidator := cryptography.GenerateKeyPair("", "", nil)
		setupRecoveryCoreGenesisAndLocalEpoch(t, coreValidator)
		proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{nonQuorumValidator})
		proof.EpochData.NextEpochQuorum = []string{coreValidator.Pub}
		proof.EpochData.NextEpochValidatorsRegistry = []string{coreValidator.Pub}
		proof.EpochData.NextEpochLeadersSequence = []string{coreValidator.Pub}
		proof.EpochDataHash = utils.ComputeEpochDataHash(&proof.EpochData)
		globals.CONFIGURATION.PointOfDistributionWS = startEpochRotationProofPoDServer(t, proof)

		ctx := callRecoveryRoute("/recovery/core_quorum/1", func(r *router.Router) {
			r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "No epoch rotation proof found for this epoch")
	})

	t.Run("peer anchor proof with invalid recovery signature is ignored", func(t *testing.T) {
		localAnchor := cryptography.GenerateKeyPair("", "", nil)
		globals.CONFIGURATION.PublicKey = localAnchor.Pub
		globals.CONFIGURATION.PrivateKey = localAnchor.Prv
		routes.ResetRecoveryCoreQuorumViewForTest()
		closeAnchorsPoDConnectionForRecoveryTest(t)
		databases.EPOCH_DATA = openTempDB(t, "epoch-data")
		databases.APPROVEMENT_THREAD_METADATA = openTempDB(t, "approvement-thread-metadata")

		coreValidator := cryptography.GenerateKeyPair("", "", nil)
		setupRecoveryCoreGenesisAndLocalEpoch(t, coreValidator)
		proof := buildSignedEpochRotationProof(t, 0, 1, []cryptography.Ed25519Box{coreValidator})

		peerAnchor := cryptography.GenerateKeyPair("", "", nil)
		peerAnchorURL := startPeerRecoveryAnchorServerWithInvalidSignature(t, peerAnchor, proof)
		setupRecoveryPeerAnchorForTest(t, localAnchor.Pub, peerAnchor.Pub, peerAnchorURL)
		globals.CONFIGURATION.PointOfDistributionWS = startEmptyAlfpPodServer(t)

		ctx := callRecoveryRoute("/recovery/core_quorum/1", func(r *router.Router) {
			r.GET("/recovery/core_quorum/{epoch}", routes.GetRecoveryCoreQuorum)
		})

		assertJSONError(t, ctx, fasthttp.StatusNotFound, "No epoch rotation proof found for this epoch")
	})
}

func buildSignedEpochRotationProof(t *testing.T, epochId, nextEpochId int, quorum []cryptography.Ed25519Box) *structures.AggregatedEpochRotationProof {
	t.Helper()

	nextEpochData := structures.NextEpochData{
		NextEpochHash:               "epoch-" + strconv.Itoa(nextEpochId) + "-hash",
		NextEpochValidatorsRegistry: []string{quorum[0].Pub},
		NextEpochQuorum:             []string{quorum[0].Pub},
		NextEpochLeadersSequence:    []string{quorum[0].Pub},
		NextEpochStartTimestamp:     123456789,
	}
	epochDataHash := utils.ComputeEpochDataHash(&nextEpochData)
	payload := utils.BuildEpochRotationProofSigningPayload(
		epochId,
		nextEpochId,
		epochDataHash,
		10,
		"0:leader:1",
		"finished-block-hash",
	)

	proofs := make(map[string]string, len(quorum))
	for _, member := range quorum {
		proofs[member.Pub] = cryptography.GenerateSignature(member.Prv, payload)
	}

	return &structures.AggregatedEpochRotationProof{
		EpochId:           epochId,
		NextEpochId:       nextEpochId,
		EpochData:         nextEpochData,
		EpochDataHash:     epochDataHash,
		FinishedOnHeight:  10,
		FinishedOnBlockId: "0:leader:1",
		FinishedOnHash:    "finished-block-hash",
		Proofs:            proofs,
	}
}

func setupRecoveryCoreGenesisAndLocalEpoch(t *testing.T, coreValidator cryptography.Ed25519Box) {
	t.Helper()

	globals.CORE_GENESIS = structures.CoreGenesis{
		Validators: []structures.CoreValidatorStorage{
			{
				Pubkey:          coreValidator.Pub,
				ValidatorUrl:    "http://core-validator",
				WssValidatorUrl: "ws://core-validator",
			},
		},
	}
	utils.ResetCoreValidatorEndpointCacheForTest()
	utils.PersistCoreQuorumState(&structures.CoreQuorumState{LatestEpochId: 0})
	utils.PersistCoreEpochData(&structures.CoreEpochData{
		EpochId:         0,
		EpochHash:       "epoch-0-hash",
		Quorum:          []string{coreValidator.Pub},
		LeadersSequence: []string{coreValidator.Pub},
	})
}

func setupRecoveryPeerAnchorForTest(t *testing.T, localAnchorPub, peerAnchorPub, peerAnchorURL string) {
	t.Helper()

	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()
	handlers.APPROVEMENT_THREAD_METADATA.Handler = structures.ApprovementThreadMetadataHandler{
		EpochDataHandler: structures.EpochDataHandler{
			Id:              0,
			Hash:            "anchor-epoch-0",
			AnchorsRegistry: []string{localAnchorPub, peerAnchorPub},
			Quorum:          []string{localAnchorPub, peerAnchorPub},
		},
	}
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()
	writeAnchorStorageToApprovementDB(t, structures.AnchorStorage{
		Pubkey:    peerAnchorPub,
		AnchorUrl: peerAnchorURL,
	})
}

func callRecoveryRoute(path string, register func(*router.Router)) *fasthttp.RequestCtx {
	r := router.New()
	register(r)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodGet)
	ctx.Request.SetRequestURI(path)
	r.Handler(ctx)

	return ctx
}

func configureRecoverySigningKey(t *testing.T) {
	t.Helper()

	keyPair := cryptography.GenerateKeyPair("", "", nil)
	globals.CONFIGURATION.PublicKey = keyPair.Pub
	globals.CONFIGURATION.PrivateKey = keyPair.Prv
}

func assertSignedRecoveryCoreQuorum(
	t *testing.T,
	ctx *fasthttp.RequestCtx,
	expectedProof *structures.AggregatedEpochRotationProof,
	expectedSource string,
	expectedFromEpoch int,
) {
	t.Helper()

	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var signed structures.RecoverySignedResponse
	decodeJSONResponse(t, ctx, &signed)
	assertSignedRecoveryPayload(t, signed)

	var payload structures.RecoveryCoreQuorumPayload
	if err := json.Unmarshal(signed.Payload, &payload); err != nil {
		t.Fatalf("failed to decode signed payload: %v", err)
	}

	if payload.Proof == nil || payload.Proof.NextEpochId != expectedProof.NextEpochId {
		t.Fatalf("unexpected recovery proof payload: %+v", payload.Proof)
	}
	if payload.RecoveryViewEpoch != expectedProof.NextEpochId ||
		payload.RecoveryViewEpochDataHash != expectedProof.EpochDataHash ||
		payload.RecoveryViewSource != expectedSource ||
		payload.RecoveryViewFromEpoch != expectedFromEpoch ||
		payload.RecoveryViewVerifiedAtMs <= 0 {
		t.Fatalf("unexpected recovery view metadata: %+v", payload)
	}

	endpoint, ok := payload.ValidatorEndpoints[expectedProof.EpochData.NextEpochQuorum[0]]
	if !ok {
		t.Fatalf("expected next quorum validator endpoint in payload: %+v", payload.ValidatorEndpoints)
	}
	if endpoint.ValidatorUrl != "http://core-validator" || endpoint.WssValidatorUrl != "ws://core-validator" {
		t.Fatalf("unexpected validator endpoints: %+v", endpoint)
	}
}

func assertSignedRecoveryPayload(t *testing.T, signed structures.RecoverySignedResponse) {
	t.Helper()

	if signed.PubKey != globals.CONFIGURATION.PublicKey {
		t.Fatalf("unexpected signing pubkey: got %q want %q", signed.PubKey, globals.CONFIGURATION.PublicKey)
	}
	if len(signed.Payload) == 0 || signed.Signature == "" {
		t.Fatalf("expected non-empty signed recovery response, got %+v", signed)
	}
	if !cryptography.VerifySignature(string(signed.Payload), signed.PubKey, signed.Signature) {
		t.Fatalf("recovery response signature does not verify")
	}
}

func assertJSONError(t *testing.T, ctx *fasthttp.RequestCtx, expectedStatus int, expectedMessage string) {
	t.Helper()

	if ctx.Response.StatusCode() != expectedStatus {
		t.Fatalf("expected status %d, got %d body=%s", expectedStatus, ctx.Response.StatusCode(), ctx.Response.Body())
	}

	var body struct {
		Err string `json:"err"`
	}
	decodeJSONResponse(t, ctx, &body)
	if body.Err != expectedMessage {
		t.Fatalf("expected error %q, got %q", expectedMessage, body.Err)
	}
}

func decodeJSONResponse(t *testing.T, ctx *fasthttp.RequestCtx, out any) {
	t.Helper()

	if err := json.Unmarshal(ctx.Response.Body(), out); err != nil {
		t.Fatalf("failed to decode response body %q: %v", ctx.Response.Body(), err)
	}
}

func openTempDB(t *testing.T, name string) *leveldb.DB {
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

func startEpochRotationProofPoDServer(t *testing.T, proof *structures.AggregatedEpochRotationProof) string {
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
			respBytes, err := json.Marshal(struct {
				Proof *structures.AggregatedEpochRotationProof `json:"proof"`
			}{Proof: proof})
			if err != nil {
				t.Errorf("failed to encode PoD response: %v", err)
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

func startPeerRecoveryAnchorServer(t *testing.T, peer cryptography.Ed25519Box, proof *structures.AggregatedEpochRotationProof) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/recovery/core_quorum/"+strconv.Itoa(proof.NextEpochId) {
			http.NotFound(w, r)
			return
		}

		payloadBytes, err := json.Marshal(structures.RecoveryCoreQuorumPayload{
			Proof: proof,
			ValidatorEndpoints: map[string]structures.RecoveryValidatorEndpoints{
				proof.EpochData.NextEpochQuorum[0]: {
					ValidatorUrl:    "http://core-validator",
					WssValidatorUrl: "ws://core-validator",
				},
			},
			RecoveryViewEpoch:         proof.NextEpochId,
			RecoveryViewEpochDataHash: proof.EpochDataHash,
			RecoveryViewSource:        "peer_test",
			RecoveryViewFromEpoch:     proof.EpochId,
			RecoveryViewVerifiedAtMs:  1,
		})
		if err != nil {
			t.Errorf("failed to encode peer recovery payload: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(structures.RecoverySignedResponse{
			PubKey:    peer.Pub,
			Payload:   payloadBytes,
			Signature: cryptography.GenerateSignature(peer.Prv, string(payloadBytes)),
		})
	}))
	t.Cleanup(server.Close)

	return server.URL
}

func startPeerRecoveryAnchorServerWithInvalidSignature(
	t *testing.T,
	peer cryptography.Ed25519Box,
	proof *structures.AggregatedEpochRotationProof,
) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/recovery/core_quorum/"+strconv.Itoa(proof.NextEpochId) {
			http.NotFound(w, r)
			return
		}

		payloadBytes, err := json.Marshal(structures.RecoveryCoreQuorumPayload{
			Proof: proof,
			ValidatorEndpoints: map[string]structures.RecoveryValidatorEndpoints{
				proof.EpochData.NextEpochQuorum[0]: {
					ValidatorUrl:    "http://core-validator",
					WssValidatorUrl: "ws://core-validator",
				},
			},
			RecoveryViewEpoch:         proof.NextEpochId,
			RecoveryViewEpochDataHash: proof.EpochDataHash,
			RecoveryViewSource:        "peer_test",
			RecoveryViewFromEpoch:     proof.EpochId,
			RecoveryViewVerifiedAtMs:  1,
		})
		if err != nil {
			t.Errorf("failed to encode peer recovery payload: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_ = json.NewEncoder(w).Encode(structures.RecoverySignedResponse{
			PubKey:    peer.Pub,
			Payload:   payloadBytes,
			Signature: "invalid-signature",
		})
	}))
	t.Cleanup(server.Close)

	return server.URL
}

func writeAnchorStorageToApprovementDB(t *testing.T, storage structures.AnchorStorage) {
	t.Helper()

	raw, err := json.Marshal(storage)
	if err != nil {
		t.Fatalf("failed to encode anchor storage: %v", err)
	}
	if err := databases.APPROVEMENT_THREAD_METADATA.Put([]byte(storage.Pubkey+"_ANCHOR_STORAGE"), raw, nil); err != nil {
		t.Fatalf("failed to store anchor storage: %v", err)
	}
}

func closeAnchorsPoDConnectionForRecoveryTest(t *testing.T) {
	t.Helper()

	if websocket_pack.ANCHORS_POD_CONNECTION != nil {
		_ = websocket_pack.ANCHORS_POD_CONNECTION.Close()
		websocket_pack.ANCHORS_POD_CONNECTION = nil
	}
	t.Cleanup(func() {
		if websocket_pack.ANCHORS_POD_CONNECTION != nil {
			_ = websocket_pack.ANCHORS_POD_CONNECTION.Close()
			websocket_pack.ANCHORS_POD_CONNECTION = nil
		}
		routes.ResetRecoveryCoreQuorumViewForTest()
	})
}
