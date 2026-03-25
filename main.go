package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"syscall"

	"github.com/modulrcloud/modulr-anchors-core/globals"
	"github.com/modulrcloud/modulr-anchors-core/utils"
)

func main() {

	//_____________________________________________________CONFIG_PROCESS____________________________________________________

	configsRawJson, readError := os.ReadFile(globals.CHAINDATA_PATH + "/configs.json")

	if readError != nil {

		panic("Error while reading configs: " + readError.Error())

	}

	if err := json.Unmarshal(configsRawJson, &globals.CONFIGURATION); err != nil {

		panic("Error with configs parsing: " + err.Error())

	}

	//_____________________________________________________READ GENESIS______________________________________________________

	genesisRawJson, readError := os.ReadFile(globals.CHAINDATA_PATH + "/genesis.json")

	if readError != nil {

		panic("Error while reading genesis: " + readError.Error())

	}

	if err := json.Unmarshal(genesisRawJson, &globals.GENESIS); err != nil {

		panic("Error with genesis parsing: " + err.Error())

	}

	//_________________________________________________READ CORE GENESIS____________________________________________________

	coreGenesisRawJson, readError := os.ReadFile(globals.CHAINDATA_PATH + "/core_genesis.json")

	if readError != nil {

		panic("Error while reading core genesis: " + readError.Error())

	}

	if err := json.Unmarshal(coreGenesisRawJson, &globals.CORE_GENESIS); err != nil {

		panic("Error with core genesis parsing: " + err.Error())

	}

	username := "unknown"
	if currentUser, err := user.Current(); err == nil {
		username = currentUser.Username
	}

	utils.PrintBanner()

	statsStringToPrint := fmt.Sprintf("System info \x1b[31mgolang:%s \033[36;1m/\x1b[31m os info:%s # %s # cpu:%d \033[36;1m/\x1b[31m runned as:%s\x1b[0m", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), username)

	utils.LogWithTime(statsStringToPrint, utils.CYAN_COLOR)

	go signalHandler()

	// Function that runs the main logic

	RunAnchorsChains()

}

// Function to handle Ctrl+C interruptions
func signalHandler() {

	sig := make(chan os.Signal, 1)

	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	<-sig

	utils.GracefulShutdown()

}
