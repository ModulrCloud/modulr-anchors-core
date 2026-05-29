package testenv

import (
	"os"
)

func init() {
	if os.Getenv("CHAINDATA_PATH") != "" {
		return
	}

	path, err := os.MkdirTemp("", "anchors-chaindata")
	if err != nil {
		return
	}

	_ = os.Setenv("CHAINDATA_PATH", path)
}
