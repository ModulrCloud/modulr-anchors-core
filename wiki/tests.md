# Test Coverage

This document describes the critical recovery and consensus flows covered by tests.

## Recovery

- Recovery routes return signed core quorum data. Tests verify both `latest_core_quorum` and `core_quorum/{epoch}`, so recovery tooling can ask an anchor for the latest known core epoch or for a specific epoch and validate the anchor signature.

- Recovery routes return clear errors when the anchor does not have enough state. Tests cover missing core quorum state, genesis-only state, missing epoch rotation proofs, and invalid epoch parameters.

- In-memory recovery catch-up works from local storage. Tests start an anchor with an older core quorum state, provide a locally stored epoch rotation proof, and verify that the recovery response is built from the caught-up in-memory view without mutating durable state.

- In-memory recovery catch-up works from the Anchors-PoD. Tests simulate a PoD that returns an epoch rotation proof and verify that the anchor can use it to advance its recovery view.

- In-memory recovery catch-up works from peer anchors. Tests simulate a peer anchor HTTP recovery endpoint and verify that a lagging anchor can fetch, validate, and use the peer's signed recovery payload.

- External recovery catch-up rejects tampered epoch data. Tests corrupt the epoch data hash and verify that the anchor refuses to build a recovery view from that proof.

- External recovery catch-up rejects proofs signed outside the current core quorum. Tests provide a proof signed by a non-quorum validator and verify that the anchor does not accept it.

- External recovery catch-up ignores peer anchor responses with invalid recovery signatures. Tests ensure that a peer response is not trusted unless the signed wrapper verifies.

## ALFP Collection

- Anchor-side ALFP collection falls back to the core quorum when the PoD has no proof. Tests simulate an empty PoD and verify that the anchor opens requests to core validators instead of giving up.

- The anchor collects ALFP signatures from core validators and builds the aggregated proof locally. Tests use fake core validators that sign the leader finalization payload, then verify that the anchor creates an ALFP from those signatures rather than fetching a ready-made proof from an API.

- ALFP collection converges through `UPGRADE` responses. Tests make core validators first return a higher voting stat, then verify that the anchor stores the upgraded skip data and succeeds on the next collection tick.

- Collected ALFPs are verified against the core quorum. Tests verify the final aggregated proof before accepting it into the anchor mempool.

## Anchor Rotation / AARP

- Anchor rotation proof route returns `UPGRADE` when the local voting stat is ahead. Tests send a stale rotation proposal and verify that the receiving anchor returns its newer voting stat instead of signing stale data.

- Anchor rotation proof route signs matching rotation proposals. Tests send a proposal that matches local state and verify that the response signature matches the expected AARP signing payload.

- Aggregated anchor rotation proofs are accepted only with a valid quorum proof. Tests submit a valid AARP and verify that it is persisted and marked for delivery suppression.

- Invalid AARP payloads are rejected and not persisted. Tests tamper with the voting stat and verify that the route rejects the proof.

- AARP collector converges through `UPGRADE`. Tests simulate quorum members that first return a higher voting stat, verify that the collector updates local state, and then verify that the next tick collects quorum signatures and stores the final AARP.
