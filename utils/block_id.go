package utils

import (
	"fmt"
	"strconv"
	"strings"
)

type ParsedBlockID struct {
	Epoch   int
	Creator string
	Index   int
}

func ParseBlockID(blockID string) (ParsedBlockID, error) {
	parts := strings.Split(blockID, ":")
	if len(parts) != 3 {
		return ParsedBlockID{}, fmt.Errorf("invalid blockId format")
	}

	epoch, err := strconv.Atoi(parts[0])
	if err != nil {
		return ParsedBlockID{}, fmt.Errorf("invalid block epoch")
	}

	index, err := strconv.Atoi(parts[2])
	if err != nil {
		return ParsedBlockID{}, fmt.Errorf("invalid block index")
	}

	return ParsedBlockID{
		Epoch:   epoch,
		Creator: parts[1],
		Index:   index,
	}, nil
}

func FormatBlockID(epoch int, creator string, index int) string {
	return fmt.Sprintf("%d:%s:%d", epoch, creator, index)
}
