package utils

import "sync"

var blockCreatorMutexRegistry = struct {
	sync.RWMutex
	data map[string]*sync.Mutex
}{data: make(map[string]*sync.Mutex)}

// GetBlockCreatorMutex returns a mutex dedicated to the provided creator.
// All routes that update per-creator voting data should lock this mutex to
// avoid races between HTTP and websocket handlers.
func GetBlockCreatorMutex(creator string) *sync.Mutex {
	blockCreatorMutexRegistry.RLock()
	mutex, ok := blockCreatorMutexRegistry.data[creator]
	blockCreatorMutexRegistry.RUnlock()
	if ok {
		return mutex
	}

	blockCreatorMutexRegistry.Lock()
	defer blockCreatorMutexRegistry.Unlock()
	if mutex, ok = blockCreatorMutexRegistry.data[creator]; ok {
		return mutex
	}
	mutex = &sync.Mutex{}
	blockCreatorMutexRegistry.data[creator] = mutex
	return mutex
}
