package globals

import (
	"strconv"
	"strings"
	"sync"
)

type BlockCreatorsMutexRegistry struct {
	sync.RWMutex
	data map[string]*sync.Mutex
}

var BLOCK_CREATORS_MUTEX_REGISTRY = BlockCreatorsMutexRegistry{
	data: make(map[string]*sync.Mutex),
}

// GetMutex returns a mutex dedicated to the provided creator within
// a specific epoch. This lets the same creator obtain separate locks for
// different epochs, allowing concurrent proof generation across epochs while
// keeping per-epoch requests serialized.
func (registry *BlockCreatorsMutexRegistry) GetMutex(epochIndex int, creator string) *sync.Mutex {

	key := strconv.Itoa(epochIndex) + ":" + creator

	registry.RLock()
	mutex, ok := registry.data[key]
	registry.RUnlock()

	if ok {
		return mutex
	}

	registry.Lock()
	defer registry.Unlock()

	if mutex, ok = registry.data[key]; ok {
		return mutex
	}

	mutex = &sync.Mutex{}

	registry.data[key] = mutex

	return mutex
}

// DeleteEpoch removes all cached creator mutexes for the provided epoch index.
// This prevents unbounded growth of the registry across epochs.
func (registry *BlockCreatorsMutexRegistry) DeleteEpoch(epochIndex int) {
	prefix := strconv.Itoa(epochIndex) + ":"
	registry.Lock()
	defer registry.Unlock()
	for key := range registry.data {
		if strings.HasPrefix(key, prefix) {
			delete(registry.data, key)
		}
	}
}
