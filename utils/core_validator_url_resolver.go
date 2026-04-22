// Package utils — core validator URL resolver.
//
// To collect ALFPs from a core quorum the anchor needs WSS endpoints for every
// quorum member. CORE_GENESIS gives us URLs for the genesis validator set, but
// validators that joined later are not present there and their URLs are not
// propagated through AggregatedEpochRotationProof either (the rotation proof
// only carries pubkeys).
//
// This file implements a small two-tier resolver:
//
//  1. In-process map populated from CORE_GENESIS at startup. Lookups are O(1)
//     and never go to the network. Suitable for stable, well-known validators.
//
//  2. HTTP fallback that calls the configured CoreBootstrapNodes:
//     GET {bootstrap}/get_validator_ws_endpoints?pubkeys=pk1,pk2,...
//     The first bootstrap that returns at least one valid mapping wins.
//     Resolved URLs are cached in the same in-process map so subsequent lookups
//     for the same pubkey skip the network entirely.
//
// The resolver is intentionally best-effort: missing/unreachable bootstrap nodes
// or validators with no published WSS URL are simply skipped — callers handle
// "no URL for pubkey X" by not opening a WS connection to that quorum member.
package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/globals"
)

const (
	coreValidatorUrlResolverHttpTimeout = 2 * time.Second
	coreValidatorUrlResolverMaxBatch    = 256

	// coreValidatorUrlsSoftCap bounds how many dynamically-resolved entries
	// can accumulate in the cache. When exceeded, every non-genesis entry is
	// evicted in one sweep; the next ResolveCoreValidatorWsUrls call will
	// re-fetch the URLs it actually needs from bootstrap nodes. Genesis
	// entries are pinned and never evicted so the bootstrap snapshot remains
	// intact for the lifetime of the process.
	coreValidatorUrlsSoftCap = 5000
)

var (
	coreValidatorUrlsMu       sync.RWMutex
	coreValidatorUrls         = make(map[string]string)
	coreValidatorUrlsGenesis  = make(map[string]struct{}) // pubkeys seeded from CORE_GENESIS (pinned)
	coreValidatorUrlsBootOnce sync.Once

	coreValidatorUrlsHttpClient = &http.Client{Timeout: coreValidatorUrlResolverHttpTimeout}
)

// initCoreValidatorUrlsFromGenesis seeds the cache with whatever URLs are
// present in CORE_GENESIS. Idempotent and safe to call many times.
func initCoreValidatorUrlsFromGenesis() {
	coreValidatorUrlsBootOnce.Do(func() {
		coreValidatorUrlsMu.Lock()
		defer coreValidatorUrlsMu.Unlock()

		for _, v := range globals.CORE_GENESIS.Validators {
			if v.Pubkey == "" || v.WssValidatorUrl == "" {
				continue
			}
			coreValidatorUrls[v.Pubkey] = v.WssValidatorUrl
			coreValidatorUrlsGenesis[v.Pubkey] = struct{}{}
		}
	})
}

// GetCoreValidatorWsUrl returns the WSS endpoint for `pubkey` from the local
// cache (CORE_GENESIS + previously resolved). Returns "" when unknown.
// Does NOT trigger HTTP resolution — use ResolveCoreValidatorWsUrls for that.
func GetCoreValidatorWsUrl(pubkey string) string {
	initCoreValidatorUrlsFromGenesis()

	coreValidatorUrlsMu.RLock()
	defer coreValidatorUrlsMu.RUnlock()
	return coreValidatorUrls[pubkey]
}

// ResolveCoreValidatorWsUrls returns a {pubkey: wssUrl} map for `pubkeys`,
// using the local cache first and falling back to bootstrap-node HTTP resolution
// for the remainder. Pubkeys that cannot be resolved are simply omitted from
// the returned map (caller treats them as "no URL available").
//
// The resolver makes at most one HTTP request per bootstrap node per call,
// batching all unresolved pubkeys into a single request. It stops as soon as
// it has filled in everything it asked for.
func ResolveCoreValidatorWsUrls(pubkeys []string) map[string]string {
	initCoreValidatorUrlsFromGenesis()

	resolved := make(map[string]string, len(pubkeys))
	var missing []string

	coreValidatorUrlsMu.RLock()
	for _, pk := range pubkeys {
		if pk == "" {
			continue
		}
		if url, ok := coreValidatorUrls[pk]; ok && url != "" {
			resolved[pk] = url
			continue
		}
		missing = append(missing, pk)
	}
	coreValidatorUrlsMu.RUnlock()

	if len(missing) == 0 {
		return resolved
	}

	bootstraps := append([]string(nil), globals.CONFIGURATION.CoreBootstrapNodes...)
	if len(bootstraps) == 0 {
		LogWithTimeThrottled(
			"core_validator_url_resolver:no_bootstraps",
			30*time.Second,
			fmt.Sprintf("Core validator URL resolver: %d unresolved pubkeys but CORE_BOOTSTRAP_NODES is empty", len(missing)),
			YELLOW_COLOR,
		)
		return resolved
	}

	// Cap the batch size; if the caller asked for more, do multiple requests.
	for start := 0; start < len(missing); start += coreValidatorUrlResolverMaxBatch {
		end := start + coreValidatorUrlResolverMaxBatch
		if end > len(missing) {
			end = len(missing)
		}
		chunk := missing[start:end]

		fetched := fetchValidatorUrlsFromBootstraps(chunk, bootstraps)
		if len(fetched) == 0 {
			continue
		}

		coreValidatorUrlsMu.Lock()
		for pk, url := range fetched {
			coreValidatorUrls[pk] = url
			resolved[pk] = url
		}
		// Soft cap: once the cache has grown past the threshold, sweep every
		// non-genesis entry. This keeps memory bounded across long-running
		// nodes even as the core validator set rotates over many epochs.
		// The freshly-added entries from `fetched` are preserved because
		// we just wrote them above; entries from *previous* Resolve calls
		// that aren't pinned get dropped.
		if len(coreValidatorUrls) > coreValidatorUrlsSoftCap {
			for pk := range coreValidatorUrls {
				if _, pinned := coreValidatorUrlsGenesis[pk]; pinned {
					continue
				}
				if _, justAdded := fetched[pk]; justAdded {
					continue
				}
				delete(coreValidatorUrls, pk)
			}
		}
		coreValidatorUrlsMu.Unlock()
	}

	return resolved
}

// fetchValidatorUrlsFromBootstraps tries each bootstrap node in order and
// returns the first non-empty response. Bootstraps that fail (network/parse
// errors) are skipped. The returned map only contains pubkeys with non-empty
// WSS URLs.
func fetchValidatorUrlsFromBootstraps(pubkeys []string, bootstraps []string) map[string]string {
	if len(pubkeys) == 0 || len(bootstraps) == 0 {
		return nil
	}

	query := strings.Join(pubkeys, ",")

	for _, base := range bootstraps {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}

		url := base + "/get_validator_ws_endpoints?pubkeys=" + query

		resp, err := coreValidatorUrlsHttpClient.Get(url)
		if err != nil {
			LogWithTimeThrottled(
				"core_validator_url_resolver:http_err:"+base,
				10*time.Second,
				fmt.Sprintf("Core validator URL resolver: GET %s failed: %v", base, err),
				YELLOW_COLOR,
			)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			LogWithTimeThrottled(
				"core_validator_url_resolver:http_status:"+base,
				10*time.Second,
				fmt.Sprintf("Core validator URL resolver: %s returned HTTP %d", base, resp.StatusCode),
				YELLOW_COLOR,
			)
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if err != nil {
			continue
		}

		var endpoints map[string]string
		if json.Unmarshal(body, &endpoints) != nil {
			continue
		}

		out := make(map[string]string, len(endpoints))
		for pk, url := range endpoints {
			if url != "" {
				out[pk] = url
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	return nil
}
