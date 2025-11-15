package structures

type NetworkParameters struct {
	QuorumSize                         int   `json:"QUORUM_SIZE"`
	EpochDuration                      int64 `json:"EPOCH_DURATION"`
	BlockTime                          int64 `json:"BLOCK_TIME"`
	MaxBlockSizeInBytes                int64 `json:"MAX_BLOCK_SIZE_IN_BYTES"`
	TxLimitPerBlock                    int   `json:"TXS_LIMIT_PER_BLOCK"`
	MaxEpochsToSupport                 int   `json:"MAX_EPOCHS_TO_SUPPORT"`
	BlockCreatorsHealthCheckIntervalMs int64 `json:"BLOCK_CREATORS_HEALTH_CHECK_INTERVAL_MS"`
}

func (src *NetworkParameters) CopyNetworkParameters() NetworkParameters {
	return NetworkParameters{
		QuorumSize:                         src.QuorumSize,
		EpochDuration:                      src.EpochDuration,
		BlockTime:                          src.BlockTime,
		MaxBlockSizeInBytes:                src.MaxBlockSizeInBytes,
		TxLimitPerBlock:                    src.TxLimitPerBlock,
		MaxEpochsToSupport:                 src.MaxEpochsToSupport,
		BlockCreatorsHealthCheckIntervalMs: src.BlockCreatorsHealthCheckIntervalMs,
	}
}

type AnchorsStorage struct {
	Pubkey       string `json:"pubkey"`
	AnchorUrl    string `json:"anchorURL"`
	WssAnchorUrl string `json:"wssAnchorURL"`
}

type Genesis struct {
	NetworkId                string            `json:"NETWORK_ID"`
	FirstEpochStartTimestamp uint64            `json:"FIRST_EPOCH_START_TIMESTAMP"`
	NetworkParameters        NetworkParameters `json:"NETWORK_PARAMETERS"`
	Anchors                  []AnchorsStorage  `json:"ANCHORS"`
}
