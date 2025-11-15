package handlers

import (
	"sync"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

var GENERATION_THREAD_METADATA = struct {
	sync.RWMutex
	Handlers map[string]*structures.GenerationThreadMetadataHandler
}{Handlers: make(map[string]*structures.GenerationThreadMetadataHandler)}

var APPROVEMENT_THREAD_METADATA = struct {
	RWMutex sync.RWMutex
	Handler structures.ApprovementThreadMetadataHandler
}{}
