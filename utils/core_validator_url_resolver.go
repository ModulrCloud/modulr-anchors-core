// Package utils — core validator URL resolver.
//
// To collect ALFPs from a core quorum the anchor needs WSS endpoints for every
// quorum member. Recovery flows additionally need the plain-HTTP validator URL
// to query /recovery/last_finalized_height. CORE_GENESIS gives us URLs for the
// genesis validator set, but validators that joined later are not present
// there and their URLs are not propagated through AggregatedEpochRotationProof
// either (the rotation proof only carries pubkeys).
//
// This file implements a small two-tier resolver:
//
//  1. In-process map populated from CORE_GENESIS at startup. Lookups are O(1)
//     and never go to the network. Suitable for stable, well-known validators.
//
//  2. HTTP fallback that calls the configured CoreBootstrapNodes:
//     GET {bootstrap}/get_validator_endpoints?pubkeys=pk1,pk2,...
//     The first bootstrap that returns at least one valid mapping wins.
//     Resolved URLs are cached in the same in-process map so subsequent lookups
//     for the same pubkey skip the network entirely.
//
// The resolver is intentionally best-effort: missing/unreachable bootstrap nodes
// or validators with no published URL are simply skipped — callers handle
// "no URL for pubkey X" by not opening a WS connection / not contacting that
// quorum member.
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
	// evicted in one sweep; the next ResolveCoreValidatorEndpoints call will
	// re-fetch the URLs it actually needs from bootstrap nodes. Genesis
	// entries are pinned and never evicted so the bootstrap snapshot remains
	// intact for the lifetime of the process.
	coreValidatorUrlsSoftCap = 5000
)

// CoreValidatorEndpoints carries the two URLs the anchor knows for a validator.
// Either field may be empty if the validator hasn't published it.
type CoreValidatorEndpoints struct {
	ValidatorUrl    string
	WssValidatorUrl string
}

var (
	coreValidatorUrlsMu       sync.RWMutex
	coreValidatorEndpoints    = make(map[string]CoreValidatorEndpoints)
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
			if v.Pubkey == "" {
				continue
			}
			if v.ValidatorUrl == "" && v.WssValidatorUrl == "" {
				continue
			}
			coreValidatorEndpoints[v.Pubkey] = CoreValidatorEndpoints{
				ValidatorUrl:    v.ValidatorUrl,
				WssValidatorUrl: v.WssValidatorUrl,
			}
			coreValidatorUrlsGenesis[v.Pubkey] = struct{}{}
		}
	})
}

// GetCoreValidatorEndpoints returns the cached endpoints for `pubkey`
// (CORE_GENESIS + previously resolved). The zero value is returned when the
// pubkey is unknown. Does NOT trigger HTTP resolution — use
// ResolveCoreValidatorEndpoints for that.
func GetCoreValidatorEndpoints(pubkey string) CoreValidatorEndpoints {
	initCoreValidatorUrlsFromGenesis()

	coreValidatorUrlsMu.RLock()
	defer coreValidatorUrlsMu.RUnlock()
	return coreValidatorEndpoints[pubkey]
}

// ResolveCoreValidatorEndpoints returns a {pubkey: endpoints} map for `pubkeys`,
// using the local cache first and falling back to bootstrap-node HTTP resolution
// for the remainder. Pubkeys that cannot be resolved are simply omitted from
// the returned map (caller treats them as "no URL available").
//
// The resolver makes at most one HTTP request per bootstrap node per call,
// batching all unresolved pubkeys into a single request. It stops as soon as
// it has filled in everything it asked for.
func ResolveCoreValidatorEndpoints(pubkeys []string) map[string]CoreValidatorEndpoints {
	initCoreValidatorUrlsFromGenesis()

	resolved := make(map[string]CoreValidatorEndpoints, len(pubkeys))
	var missing []string

	coreValidatorUrlsMu.RLock()
	for _, pk := range pubkeys {
		if pk == "" {
			continue
		}
		if eps, ok := coreValidatorEndpoints[pk]; ok && (eps.ValidatorUrl != "" || eps.WssValidatorUrl != "") {
			resolved[pk] = eps
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

		fetched := fetchValidatorEndpointsFromBootstraps(chunk, bootstraps)
		if len(fetched) == 0 {
			continue
		}

		coreValidatorUrlsMu.Lock()
		for pk, eps := range fetched {
			coreValidatorEndpoints[pk] = eps
			resolved[pk] = eps
		}
		// Soft cap: once the cache has grown past the threshold, sweep every
		// non-genesis entry. This keeps memory bounded across long-running
		// nodes even as the core validator set rotates over many epochs.
		if len(coreValidatorEndpoints) > coreValidatorUrlsSoftCap {
			for pk := range coreValidatorEndpoints {
				if _, pinned := coreValidatorUrlsGenesis[pk]; pinned {
					continue
				}
				if _, justAdded := fetched[pk]; justAdded {
					continue
				}
				delete(coreValidatorEndpoints, pk)
			}
		}
		coreValidatorUrlsMu.Unlock()
	}

	return resolved
}

// ResolveCoreValidatorWsUrls is a backwards-compatible wrapper around
// ResolveCoreValidatorEndpoints that returns only the WSS URL per pubkey.
// Pubkeys with no resolvable WSS URL are dropped from the result.
func ResolveCoreValidatorWsUrls(pubkeys []string) map[string]string {
	endpoints := ResolveCoreValidatorEndpoints(pubkeys)
	out := make(map[string]string, len(endpoints))
	for pk, eps := range endpoints {
		if eps.WssValidatorUrl != "" {
			out[pk] = eps.WssValidatorUrl
		}
	}
	return out
}

// ResetCoreValidatorEndpointCacheForTest resets the process-local resolver
// cache so tests can swap CORE_GENESIS without order-dependent behavior.
func ResetCoreValidatorEndpointCacheForTest() {
	coreValidatorUrlsMu.Lock()
	defer coreValidatorUrlsMu.Unlock()

	coreValidatorEndpoints = make(map[string]CoreValidatorEndpoints)
	coreValidatorUrlsGenesis = make(map[string]struct{})
	coreValidatorUrlsBootOnce = sync.Once{}
}

// fetchValidatorEndpointsFromBootstraps tries each bootstrap node in order and
// returns the first non-empty response. Bootstraps that fail (network/parse
// errors) are skipped. The returned map only contains pubkeys with at least
// one non-empty URL.
//
// It first tries the new /get_validator_endpoints route (returns both URLs);
// if that returns nothing it falls back to /get_validator_ws_endpoints (older
// core nodes only know the WSS-only route).
func fetchValidatorEndpointsFromBootstraps(pubkeys []string, bootstraps []string) map[string]CoreValidatorEndpoints {
	if len(pubkeys) == 0 || len(bootstraps) == 0 {
		return nil
	}

	query := strings.Join(pubkeys, ",")

	for _, base := range bootstraps {
		base = strings.TrimRight(strings.TrimSpace(base), "/")
		if base == "" {
			continue
		}

		// Try the rich endpoint first.
		if out := fetchValidatorEndpointsRich(base, query); len(out) > 0 {
			return out
		}

		// Fallback to the WSS-only endpoint.
		if out := fetchValidatorEndpointsWssOnly(base, query); len(out) > 0 {
			return out
		}
	}

	return nil
}

func fetchValidatorEndpointsRich(base, query string) map[string]CoreValidatorEndpoints {
	url := base + "/get_validator_endpoints?pubkeys=" + query

	resp, err := coreValidatorUrlsHttpClient.Get(url)
	if err != nil {
		LogWithTimeThrottled(
			"core_validator_url_resolver:http_err:"+base,
			10*time.Second,
			fmt.Sprintf("Core validator URL resolver: GET %s failed: %v", base, err),
			YELLOW_COLOR,
		)
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		// 404/400 here just means the bootstrap doesn't speak this route yet.
		// Don't log loudly — the WSS-only fallback will retry.
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	_ = resp.Body.Close()
	if err != nil {
		return nil
	}

	type richEntry struct {
		ValidatorUrl    string `json:"validatorUrl"`
		WssValidatorUrl string `json:"wssValidatorUrl"`
	}
	var endpoints map[string]richEntry
	if json.Unmarshal(body, &endpoints) != nil {
		return nil
	}

	out := make(map[string]CoreValidatorEndpoints, len(endpoints))
	for pk, e := range endpoints {
		if e.ValidatorUrl == "" && e.WssValidatorUrl == "" {
			continue
		}
		out[pk] = CoreValidatorEndpoints{
			ValidatorUrl:    e.ValidatorUrl,
			WssValidatorUrl: e.WssValidatorUrl,
		}
	}
	return out
}

func fetchValidatorEndpointsWssOnly(base, query string) map[string]CoreValidatorEndpoints {
	url := base + "/get_validator_ws_endpoints?pubkeys=" + query

	resp, err := coreValidatorUrlsHttpClient.Get(url)
	if err != nil {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
	if err != nil {
		return nil
	}

	var endpoints map[string]string
	if json.Unmarshal(body, &endpoints) != nil {
		return nil
	}

	out := make(map[string]CoreValidatorEndpoints, len(endpoints))
	for pk, wss := range endpoints {
		if wss == "" {
			continue
		}
		out[pk] = CoreValidatorEndpoints{WssValidatorUrl: wss}
	}
	return out
}
