package utils

import (
	"strconv"
	"sync"
)

var blockCreatorMutexRegistry = struct {
	sync.RWMutex
	data map[string]*sync.Mutex
}{data: make(map[string]*sync.Mutex)}

// GetBlockCreatorMutex returns a mutex dedicated to the provided creator within
// a specific epoch. This lets the same creator obtain separate locks for
// different epochs, allowing concurrent proof generation across epochs while
// keeping per-epoch requests serialized.
func GetBlockCreatorMutex(epochIndex int, creator string) *sync.Mutex {
	key := strconv.Itoa(epochIndex) + ":" + creator
	blockCreatorMutexRegistry.RLock()
	mutex, ok := blockCreatorMutexRegistry.data[key]
	blockCreatorMutexRegistry.RUnlock()
	if ok {
		return mutex
	}

	blockCreatorMutexRegistry.Lock()
	defer blockCreatorMutexRegistry.Unlock()
	if mutex, ok = blockCreatorMutexRegistry.data[key]; ok {
		return mutex
	}
	mutex = &sync.Mutex{}
	blockCreatorMutexRegistry.data[key] = mutex
	return mutex
}
