# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project Shape

- This is the `modulr-anchors-core` Go repository.
- Keep changes aligned with existing packages: `threads` for real long-running loops, `utils` for shared helpers, `websocket_pack` for WS routes/RPC structs, `http_pack/routes` for HTTP handlers, and `structures` for shared data types.
- Do not create new top-level packages unless there is a clear architectural need and the existing packages do not fit.
- A file under `threads/` should represent thread-like behavior: a long-running loop or runtime worker. One-shot helpers should live elsewhere, usually `utils`.

## Tests

- Main unit/integration test command:

```bash
go test ./tests -count=1 -v
```

- Use `-count=1` when validating changes; cached test output is not enough.
- This repository does not own the E2E harness. Local E2E scenarios are orchestrated from `modulr-core/tests_e2e/harness` and may start real anchor/core processes.
- Do not run E2E unless explicitly requested.

## Go Modules

- Do not modify `go.mod` or `go.sum` just because a local test command rewrote them.
- If Go dependency resolution fails in Cursor, check for a bad `GOMODCACHE` before changing module files.
- Prefer normal repository commands over ad hoc environment workarounds.

## Anchors-Core Rules

- `modulr-anchors-core` is reset fully during core network recovery; do not design recovery logic that assumes anchor DB durability across a recovered core network unless explicitly requested.
- `CoreQuorumState.LatestEpochId` should represent finalized core epoch knowledge from AERP-style proofs.
- Announced core epoch data may be used for ALFP verification/collection, but recovery should rely on finalized core quorum data.
- ALFP acceptance must verify that the core epoch is supported and signatures match known core quorum data.

## Concurrency And Signing

- Anchors generate blocks concurrently. Do not add global locks that serialize all creators.
- Signing/finalization paths should serialize only per `(epoch, creator)` where needed.
- Preserve the first-write-wins protection against signing conflicting blocks for the same creator/index.
- Anchor rotation collector may stop after quorum majority; tests should not require every peer response when majority is sufficient.

## Coding Style

- Keep changes narrowly scoped to the requested behavior.
- Prefer existing helpers and local patterns over new abstractions.
- Avoid unrelated refactors, formatting churn, or metadata changes.
- Run `gofmt` on changed Go files.
