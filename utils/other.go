package utils

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/modulrcloud/modulr-anchors-core/databases"
	"github.com/modulrcloud/modulr-anchors-core/globals"
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
	lines := kernelBannerLines()
	if len(lines) == 0 {
		return
	}
	PrintShellDivider()
	width := 0
	for _, line := range lines {
		if w := displayWidth(line); w > width {
			width = w
		}
	}
	top := buildPlainBorder(width)
	LogWithTime(top, "")
	for _, line := range lines {
		LogWithTime(buildPlainLine(line, width), "")
	}
	LogWithTime(top, "")
	PrintShellDivider()
}

func PrintShellDivider() {
	LogWithTime(strings.Repeat("-", 60), "")
}

func kernelBannerLines() []string {
	cfg := globals.CONFIGURATION
	params := globals.GENESIS.NetworkParameters
	lines := []string{"Modulr anchors core v0.1.0"}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("■ network id: %s", fallbackValue(globals.GENESIS.NetworkId)))
	lines = append(lines, fmt.Sprintf("■ first epoch start: %d", globals.GENESIS.FirstEpochStartTimestamp))
	lines = append(lines, fmt.Sprintf("■ http endpoint: %s", endpointLabel(cfg.Interface, cfg.Port)))
	lines = append(lines, fmt.Sprintf("■ ws endpoint: %s", endpointLabel(cfg.WebSocketInterface, cfg.WebSocketPort)))
	lines = append(lines, fmt.Sprintf("■ bootstrap peers: %d", len(cfg.BootstrapNodes)))
	lines = append(lines, fmt.Sprintf("■ quorum size: %d / block time: %dms", params.QuorumSize, params.BlockTime))
	return lines
}

func endpointLabel(host string, port int) string {
	if host == "" && port == 0 {
		return "-"
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if port == 0 {
		return host
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func fallbackValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func buildPlainBorder(width int) string {
	return "+" + strings.Repeat("-", width+2) + "+"
}

func buildPlainLine(content string, width int) string {
	padding := width - displayWidth(content)
	if padding < 0 {
		padding = 0
	}
	return fmt.Sprintf("| %s%s |", content, strings.Repeat(" ", padding))
}

func displayWidth(s string) int {
	return utf8.RuneCountInString(s)
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
