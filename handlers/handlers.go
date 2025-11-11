package handlers

import (
	"sync"

	"github.com/ModulrCloud/ModulrAnchorsCore/structures"
)

var GENERATION_THREAD_METADATA structures.GenerationThreadMetadataHandler

var APPROVEMENT_THREAD_METADATA = struct {
	RWMutex sync.RWMutex
	Handler structures.ApprovementThreadMetadataHandler
}{}
