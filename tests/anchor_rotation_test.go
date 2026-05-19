package tests

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/modulrcloud/modulr-anchors-core/tests/testenv"

	"github.com/modulrcloud/modulr-anchors-core/cryptography"
	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/handlers"
	"github.com/modulrcloud/modulr-anchors-core/http_pack/routes"
	"github.com/modulrcloud/modulr-anchors-core/structures"
	"github.com/modulrcloud/modulr-anchors-core/threads"
	"github.com/modulrcloud/modulr-anchors-core/utils"

	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

func TestRequestAnchorRotationProofSignsAndUpgrades(t *testing.T) {
	resetAnchorRotationTestState(t)

	quorum := generateAnchorRotationQuorum()
	rotatedAnchor := quorum[0].Pub
	epochHandler := setupAnchorRotationEpoch(t, quorum, rotatedAnchor, nil)
	globals.CONFIGURATION.PublicKey = quorum[1].Pub
	globals.CONFIGURATION.PrivateKey = quorum[1].Prv

	currentStat := buildAnchorRotationVotingStat(t, epochHandler, quorum, rotatedAnchor, 1, "prev-hash", "current-hash")
	if err := utils.StoreVotingStat(epochHandler.Id, rotatedAnchor, currentStat); err != nil {
		t.Fatalf("failed to store current voting stat: %v", err)
	}
	if err := utils.DisableFinalizationProofsForCreator(epochHandler.Id, rotatedAnchor); err != nil {
		t.Fatalf("failed to disable rotated anchor: %v", err)
	}

	t.Run("returns UPGRADE when local voting stat is ahead", func(t *testing.T) {
		proposal := structures.NewVotingStatTemplate()
		ctx := callAnchorRotationProofRoute(t, structures.AnchorRotationProofRequest{
			EpochIndex: epochHandler.Id,
			ForAnchor:  rotatedAnchor,
			Proposal:   proposal,
		})

		if ctx.Response.StatusCode() != fasthttp.StatusConflict {
			t.Fatalf("expected 409, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
		var resp structures.AnchorRotationProofResponse
		decodeJSONResponse(t, ctx, &resp)
		if resp.Status != "UPGRADE" || resp.VotingStat == nil || resp.VotingStat.Index != currentStat.Index || resp.VotingStat.Hash != currentStat.Hash {
			t.Fatalf("unexpected UPGRADE response: %+v", resp)
		}
	})

	t.Run("signs matching proposal", func(t *testing.T) {
		ctx := callAnchorRotationProofRoute(t, structures.AnchorRotationProofRequest{
			EpochIndex: epochHandler.Id,
			ForAnchor:  rotatedAnchor,
			Proposal:   currentStat,
		})

		if ctx.Response.StatusCode() != fasthttp.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
		}
		var resp structures.AnchorRotationProofResponse
		decodeJSONResponse(t, ctx, &resp)
		payload := utils.BuildAnchorRotationProofPayload(rotatedAnchor, currentStat.Index, currentStat.Hash, epochHandler.Id)
		if resp.Status != "OK" || !cryptography.VerifySignature(payload, globals.CONFIGURATION.PublicKey, resp.Signature) {
			t.Fatalf("unexpected signature response: %+v", resp)
		}
	})
}

func TestAcceptAggregatedAnchorRotationProofStoresOnlyValidQuorumProof(t *testing.T) {
	resetAnchorRotationTestState(t)

	quorum := generateAnchorRotationQuorum()
	rotatedAnchor := quorum[0].Pub
	epochHandler := setupAnchorRotationEpoch(t, quorum, rotatedAnchor, nil)
	globals.CONFIGURATION.PublicKey = quorum[1].Pub
	globals.CONFIGURATION.PrivateKey = quorum[1].Prv

	proof := buildAggregatedAnchorRotationProofForTest(t, epochHandler, quorum[:3], rotatedAnchor, 2, "prev-hash", "rotation-hash")
	ctx := callAcceptAnchorRotationProofRoute(t, structures.AcceptAggregatedAnchorRotationProofRequest{
		AggregatedRotationProofs: []structures.AggregatedAnchorRotationProof{proof},
	})
	if ctx.Response.StatusCode() != fasthttp.StatusOK {
		t.Fatalf("expected valid proof to be accepted, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}

	stored, err := utils.LoadAggregatedAnchorRotationProof(epochHandler.Id, rotatedAnchor)
	if err != nil {
		t.Fatalf("expected proof to be stored: %v", err)
	}
	if stored.Anchor != rotatedAnchor || stored.VotingStat.Index != proof.VotingStat.Index || !utils.IsAnchorDisabledByAarp(epochHandler.Id, rotatedAnchor) {
		t.Fatalf("unexpected stored AARP or delivery flag: stored=%+v disabled=%v", stored, utils.IsAnchorDisabledByAarp(epochHandler.Id, rotatedAnchor))
	}

	resetAnchorRotationTestState(t)
	epochHandler = setupAnchorRotationEpoch(t, quorum, rotatedAnchor, nil)
	invalid := proof
	invalid.VotingStat.Hash = "tampered-hash"
	ctx = callAcceptAnchorRotationProofRoute(t, structures.AcceptAggregatedAnchorRotationProofRequest{
		AggregatedRotationProofs: []structures.AggregatedAnchorRotationProof{invalid},
	})
	if ctx.Response.StatusCode() != fasthttp.StatusBadRequest {
		t.Fatalf("expected invalid proof to be rejected, got %d body=%s", ctx.Response.StatusCode(), ctx.Response.Body())
	}
	if loaded, err := utils.LoadAggregatedAnchorRotationProof(epochHandler.Id, rotatedAnchor); err != nil || loaded.Anchor != "" {
		t.Fatalf("did not expect invalid proof to be stored")
	}
}

func TestAnchorRotationCollectorConvergesThroughUpgrade(t *testing.T) {
	resetAnchorRotationTestState(t)

	quorum := generateAnchorRotationQuorum()
	rotatedAnchor := quorum[0].Pub
	epochHandler := setupAnchorRotationEpoch(t, quorum, rotatedAnchor, nil)
	globals.CONFIGURATION.PublicKey = quorum[0].Pub
	globals.CONFIGURATION.PrivateKey = quorum[0].Prv

	localStat := buildAnchorRotationVotingStat(t, epochHandler, quorum, rotatedAnchor, 0, "genesis-hash", "local-hash")
	upgradedStat := buildAnchorRotationVotingStat(t, epochHandler, quorum, rotatedAnchor, 1, localStat.Hash, "upgraded-hash")
	if err := utils.StoreVotingStat(epochHandler.Id, rotatedAnchor, localStat); err != nil {
		t.Fatalf("failed to store local voting stat: %v", err)
	}
	if err := utils.DisableFinalizationProofsForCreator(epochHandler.Id, rotatedAnchor); err != nil {
		t.Fatalf("failed to disable rotated anchor: %v", err)
	}

	var upgradeResponses atomic.Int32
	var okResponses atomic.Int32
	urls := make(map[string]string, len(quorum))
	for _, member := range quorum {
		urls[member.Pub] = startAnchorRotationQuorumServer(t, member, epochHandler, rotatedAnchor, upgradedStat, &upgradeResponses, &okResponses)
	}
	setupAnchorRotationEpoch(t, quorum, rotatedAnchor, urls)

	threads.RunAnchorRotationCollectorTickForTest()

	if got := upgradeResponses.Load(); got != int32(len(quorum)) {
		t.Fatalf("expected first tick to receive %d UPGRADE responses, got %d", len(quorum), got)
	}
	storedStat, err := utils.ReadVotingStat(epochHandler.Id, rotatedAnchor)
	if err != nil {
		t.Fatalf("failed to read upgraded local stat: %v", err)
	}
	if storedStat.Index != upgradedStat.Index || storedStat.Hash != upgradedStat.Hash {
		t.Fatalf("expected local voting stat to upgrade to %+v, got %+v", upgradedStat, storedStat)
	}
	if loaded, err := utils.LoadAggregatedAnchorRotationProof(epochHandler.Id, rotatedAnchor); err != nil || loaded.Anchor != "" {
		t.Fatalf("did not expect AARP before upgraded stat is signed")
	}

	threads.RunAnchorRotationCollectorTickForTest()

	if got := okResponses.Load(); got != int32(len(quorum)) {
		t.Fatalf("expected second tick to receive %d OK signatures, got %d", len(quorum), got)
	}
	proof, err := utils.LoadAggregatedAnchorRotationProof(epochHandler.Id, rotatedAnchor)
	if err != nil {
		t.Fatalf("expected AARP after upgraded stat signatures: %v", err)
	}
	if proof.VotingStat.Index != upgradedStat.Index || len(proof.Signatures) < utils.GetQuorumMajority(epochHandler) {
		t.Fatalf("unexpected collected AARP: %+v", proof)
	}
	if err := utils.VerifyAggregatedAnchorRotationProof(&proof, epochHandler); err != nil {
		t.Fatalf("collected AARP does not verify: %v", err)
	}
}

func resetAnchorRotationTestState(t *testing.T) {
	t.Helper()

	databases.FINALIZATION_VOTING_STATS = openTempDB(t, "finalization-voting-stats")
	databases.APPROVEMENT_THREAD_METADATA = openTempDB(t, "approvement-thread-metadata")
	globals.MEMPOOL.ClearEpochProofs(1)
}

func generateAnchorRotationQuorum() []cryptography.Ed25519Box {
	return []cryptography.Ed25519Box{
		cryptography.GenerateKeyPair("", "", nil),
		cryptography.GenerateKeyPair("", "", nil),
		cryptography.GenerateKeyPair("", "", nil),
		cryptography.GenerateKeyPair("", "", nil),
	}
}

func setupAnchorRotationEpoch(
	t *testing.T,
	quorum []cryptography.Ed25519Box,
	rotatedAnchor string,
	urls map[string]string,
) *structures.EpochDataHandler {
	t.Helper()

	pubkeys := make([]string, 0, len(quorum))
	for _, member := range quorum {
		pubkeys = append(pubkeys, member.Pub)
		writeAnchorStorageToApprovementDB(t, structures.AnchorStorage{
			Pubkey:    member.Pub,
			AnchorUrl: urls[member.Pub],
		})
	}
	if !containsString(pubkeys, rotatedAnchor) {
		pubkeys = append(pubkeys, rotatedAnchor)
	}

	handler := structures.EpochDataHandler{
		Id:              1,
		Hash:            "anchor-epoch-hash",
		AnchorsRegistry: pubkeys,
		Quorum:          pubkeys[:len(quorum)],
	}
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Lock()
	handlers.APPROVEMENT_THREAD_METADATA.Handler = structures.ApprovementThreadMetadataHandler{EpochDataHandler: handler}
	handlers.APPROVEMENT_THREAD_METADATA.RWMutex.Unlock()

	return &handler
}

func buildAggregatedAnchorRotationProofForTest(
	t *testing.T,
	epochHandler *structures.EpochDataHandler,
	signers []cryptography.Ed25519Box,
	rotatedAnchor string,
	index int,
	prevHash string,
	hash string,
) structures.AggregatedAnchorRotationProof {
	t.Helper()

	votingStat := buildAnchorRotationVotingStat(t, epochHandler, signers, rotatedAnchor, index, prevHash, hash)
	payload := utils.BuildAnchorRotationProofPayload(rotatedAnchor, votingStat.Index, votingStat.Hash, epochHandler.Id)
	signatures := make(map[string]string, len(signers))
	for _, signer := range signers {
		signatures[signer.Pub] = cryptography.GenerateSignature(signer.Prv, payload)
	}

	return structures.AggregatedAnchorRotationProof{
		EpochIndex: epochHandler.Id,
		Anchor:     rotatedAnchor,
		VotingStat: votingStat,
		Signatures: signatures,
	}
}

func buildAnchorRotationVotingStat(
	t *testing.T,
	epochHandler *structures.EpochDataHandler,
	signers []cryptography.Ed25519Box,
	rotatedAnchor string,
	index int,
	prevHash string,
	hash string,
) structures.VotingStat {
	t.Helper()

	blockID := strconv.Itoa(epochHandler.Id) + ":" + rotatedAnchor + ":" + strconv.Itoa(index)
	afpPayload := strings.Join([]string{prevHash, blockID, hash, strconv.Itoa(epochHandler.Id)}, ":")
	proofs := make(map[string]string, len(signers))
	for _, signer := range signers {
		proofs[signer.Pub] = cryptography.GenerateSignature(signer.Prv, afpPayload)
	}

	return structures.VotingStat{
		Index: index,
		Hash:  hash,
		Afp: structures.AggregatedFinalizationProof{
			PrevBlockHash: prevHash,
			BlockId:       blockID,
			BlockHash:     hash,
			Proofs:        proofs,
		},
	}
}

func startAnchorRotationQuorumServer(
	t *testing.T,
	member cryptography.Ed25519Box,
	epochHandler *structures.EpochDataHandler,
	rotatedAnchor string,
	upgradedStat structures.VotingStat,
	upgradeResponses *atomic.Int32,
	okResponses *atomic.Int32,
) string {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/request_anchor_rotation_proof" {
			http.NotFound(w, r)
			return
		}

		var req structures.AnchorRotationProofRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if req.Proposal.Index < upgradedStat.Index {
			upgradeResponses.Add(1)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(structures.AnchorRotationProofResponse{
				Status:     "UPGRADE",
				VotingStat: &upgradedStat,
			})
			return
		}

		payload := utils.BuildAnchorRotationProofPayload(rotatedAnchor, upgradedStat.Index, upgradedStat.Hash, epochHandler.Id)
		okResponses.Add(1)
		_ = json.NewEncoder(w).Encode(structures.AnchorRotationProofResponse{
			Status:    "OK",
			Signature: cryptography.GenerateSignature(member.Prv, payload),
		})
	}))
	t.Cleanup(server.Close)

	return server.URL
}

func callAnchorRotationProofRoute(t *testing.T, req structures.AnchorRotationProofRequest) *fasthttp.RequestCtx {
	t.Helper()

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	r := router.New()
	r.POST("/request_anchor_rotation_proof", routes.RequestAnchorRotationProof)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/request_anchor_rotation_proof")
	ctx.Request.SetBody(raw)
	r.Handler(ctx)

	return ctx
}

func callAcceptAnchorRotationProofRoute(t *testing.T, req structures.AcceptAggregatedAnchorRotationProofRequest) *fasthttp.RequestCtx {
	t.Helper()

	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}
	r := router.New()
	r.POST("/accept_aggregated_anchor_rotation_proof", routes.AcceptAggregatedAnchorRotationProofs)

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.SetMethod(fasthttp.MethodPost)
	ctx.Request.SetRequestURI("/accept_aggregated_anchor_rotation_proof")
	ctx.Request.SetBody(raw)
	r.Handler(ctx)

	return ctx
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
