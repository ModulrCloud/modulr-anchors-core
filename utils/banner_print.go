package utils

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/modulrcloud/modulr-anchors-core/globals"
)

func PrintBanner() {
	lines := bannerLines()
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

func bannerLines() []string {
	cfg := globals.CONFIGURATION
	params := globals.GENESIS.NetworkParameters
	lines := []string{"Modulr anchors core v0.1.0"}
	lines = append(lines, "")
	lines = append(lines, fmt.Sprintf("■ network id: %s", fallbackValue(globals.GENESIS.NetworkId)))
	lines = append(lines, fmt.Sprintf("■ first epoch start: %d", globals.GENESIS.FirstEpochStartTimestamp))
	lines = append(lines, fmt.Sprintf("■ http endpoint: %s", endpointLabel(cfg.Interface, cfg.Port)))
	lines = append(lines, fmt.Sprintf("■ ws endpoint: %s", endpointLabel(cfg.WebSocketInterface, cfg.WebSocketPort)))
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
