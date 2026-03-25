package globals

import (
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/modulrcloud/modulr-anchors-core/structures"
)

var CHAINDATA_PATH = func() string {

	dirPath := os.Getenv("CHAINDATA_PATH")

	if dirPath == "" {

		panic("CHAINDATA_PATH environment variable is not set")

	}

	dirPath = strings.TrimRight(dirPath, "/")

	if !filepath.IsAbs(dirPath) {

		panic("CHAINDATA_PATH must be an absolute path")

	}

	// Check if exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {

		// If no - create
		if err := os.MkdirAll(dirPath, os.ModePerm); err != nil {

			panic("Error with creating directory for chaindata: " + err.Error())

		}

	}

	return dirPath

}()

var CONFIGURATION structures.NodeLevelConfig

var GENESIS structures.Genesis

var CORE_GENESIS structures.CoreGenesis

// Flag to use in websocket & http routes to prevent flood of .RLock() calls on mutexes

var FLOOD_PREVENTION_FLAG_FOR_ROUTES atomic.Bool
