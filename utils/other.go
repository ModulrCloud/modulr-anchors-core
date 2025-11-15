package utils

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/structures"

	"lukechampine.com/blake3"
)

// ANSI escape codes for text colors
const (
	RESET_COLOR       = "\033[0m"
	RED_COLOR         = "\033[31;1m"
	DEEP_GREEN_COLOR  = "\u001b[38;5;23m"
	DEEP_YELLOW       = "\u001b[38;5;214m"
	GREEN_COLOR       = "\033[32;1m"
	YELLOW_COLOR      = "\033[33m"
	MAGENTA_COLOR     = "\033[38;5;99m"
	CYAN_COLOR        = "\033[36;1m"
	WHITE_COLOR       = "\033[37;1m"
	TIMESTAMP_COLOR   = "\u001b[38;5;245m"
	TIMESTAMP_BRACKET = "\u001b[38;5;66m"
	PID_COLOR         = "\u001b[38;5;140m"
	DIVIDER_COLOR     = "\u001b[38;5;240m"
)

var SHUTDOWN_ONCE sync.Once

var kernelBanner = []string{
	" __  __           _ _           ",
	"|  \\ \\ | ___   __| (_)_ __  ___ ",
	"| |\\/| |/ _ \\ / _` | | '_ \\ / __|",
	"| |  | | (_) | (_| | | | | \\__ \\",
	"|_|  |_|\\___/ \\__,_|_|_| |_|___/",
}

func GracefulShutdown() {

	SHUTDOWN_ONCE.Do(func() {

		LogWithTime("Stop signal has been initiated.Keep waiting...", CYAN_COLOR)

		LogWithTime("Closing server connections...", CYAN_COLOR)

		if err := databases.CloseAll(); err != nil {
			LogWithTime(fmt.Sprintf("failed to close databases: %v", err), RED_COLOR)
		}

		LogWithTime("Node was gracefully stopped", GREEN_COLOR)

		os.Exit(0)

	})

}

func LogWithTime(msg, msgColor string) {

	formattedDate := time.Now().Format("02 January 2006 15:04:05")
	timestampLabel := fmt.Sprintf("%s[%s%s%s]%s", TIMESTAMP_BRACKET, TIMESTAMP_COLOR, formattedDate, TIMESTAMP_BRACKET, RESET_COLOR)
	pidLabel := fmt.Sprintf("%s(pid:%d)%s", PID_COLOR, os.Getpid(), RESET_COLOR)
	divider := fmt.Sprintf("%s ┇ %s", DIVIDER_COLOR, RESET_COLOR)

	fmt.Printf("%s %s%s%s%s\n", timestampLabel, pidLabel, divider, msgColor, msg+RESET_COLOR)

}

func PrintKernelBanner() {
	colors := []string{CYAN_COLOR, GREEN_COLOR, YELLOW_COLOR, MAGENTA_COLOR, WHITE_COLOR}
	for idx, line := range kernelBanner {
		color := colors[idx%len(colors)]
		LogWithTime(line, color)
	}
}

func Blake3(data string) string {

	blake3Hash := blake3.Sum256([]byte(data))

	return hex.EncodeToString(blake3Hash[:])

}

func GetUTCTimestampInMilliSeconds() int64 {

	return time.Now().UTC().UnixMilli()

}

func EpochStillFresh(epochHandler *structures.EpochDataHandler, networkParams *structures.NetworkParameters) bool {

	return (epochHandler.StartTimestamp + uint64(networkParams.EpochDuration)) > uint64(GetUTCTimestampInMilliSeconds())

}

func SignalAboutEpochRotationExists(epochIndex int) bool {

	keyValue := []byte("EPOCH_FINISH:" + strconv.Itoa(epochIndex))

	if readyToChangeEpochRaw, err := databases.FINALIZATION_VOTING_STATS.Get(keyValue, nil); err == nil && string(readyToChangeEpochRaw) == "TRUE" {

		return true

	}

	return false

}
