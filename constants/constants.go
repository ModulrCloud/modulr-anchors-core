package constants

const (
	DBKeyApprovementThreadMetadata = "APPROVEMENT_THREAD_METADATA"
	DBKeyPrefixGenerationThread    = "GENERATION_THREAD_METADATA:"
	DBKeyPrefixEpochFinish         = "EPOCH_FINISH:"
	DBKeyPrefixFinalizationVote    = "FINALIZATION_VOTE:"

	// DBKeyPrefixAlfpIncluded marks (in EPOCH_DATA) that an ALFP for a (epochId, leader)
	// pair has already been included in some locally generated anchor block.
	// Used by AlfpCollectionThread to avoid re-collecting/re-pulling the same proof.
	// Format: "ALFP_INCLUDED:{epochId}:{leader}".
	DBKeyPrefixAlfpIncluded = "ALFP_INCLUDED:"

	DBKeyPrefixEpochAnnouncementProof = "EPOCH_ANNOUNCEMENT_PROOF:"

	ZeroHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
)

// SigningPrefixLeaderFinalization is the salt used by core validators when
// signing leader-finalization payloads. Anchor reproduces the exact same
// payload to verify signatures it collects from the core quorum.
// Must stay in sync with modulr-core's constants.SigningPrefixLeaderFinalization.
const SigningPrefixLeaderFinalization = "LEADER_FINALIZATION_PROOF"
const SigningPrefixEpochAnnouncement = "EPOCH_ANNOUNCEMENT_PROOF"

// WebSocket route names exposed by core nodes / unified PoD.
const (
	// WsRouteGetAggregatedLeaderFinalizationProof is the unified PoD route used
	// to fetch a fully aggregated ALFP that has already been built by some core
	// validator. Used as the cheap fast path before falling back to manual
	// signature collection.
	WsRouteGetAggregatedLeaderFinalizationProof = "get_aggregated_leader_finalization_proof"

	// WsRouteGetLeaderFinalizationProof is the core-validator route used to
	// request a single signature on a (leader, skipData, epoch) payload.
	// This is what AlfpCollectionThread fans out to the whole core quorum to
	// reconstruct an ALFP locally when modulr-core's LeaderFinalizationThread
	// is unable to deliver one in time.
	WsRouteGetLeaderFinalizationProof = "get_leader_finalization_proof"

	WsRouteGetEpochAnnouncementProofFromPoD = "get_epoch_announcement_proof_from_pod"
)
