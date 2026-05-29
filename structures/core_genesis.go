package structures

type CoreValidatorStorage struct {
	Pubkey          string            `json:"pubkey"`
	Percentage      uint8             `json:"percentage"`
	TotalStaked     uint64            `json:"totalStaked"`
	Stakers         map[string]uint64 `json:"stakers"`
	ValidatorUrl    string            `json:"validatorURL"`
	WssValidatorUrl string            `json:"wssValidatorURL"`
}

type CoreNetworkParameters struct {
	ValidatorRequiredStake uint64 `json:"VALIDATOR_REQUIRED_STAKE"`
	MinimalStakePerStaker  uint64 `json:"MINIMAL_STAKE_PER_STAKER"`
	QuorumSize             int    `json:"QUORUM_SIZE"`
	EpochDuration          int64  `json:"EPOCH_DURATION"`
	LeadershipDuration     int64  `json:"LEADERSHIP_DURATION"`
	BlockTime              int64  `json:"BLOCK_TIME"`
	MaxBlockSizeInBytes    int64  `json:"MAX_BLOCK_SIZE_IN_BYTES"`
	TxLimitPerBlock        int    `json:"TXS_LIMIT_PER_BLOCK"`
}

type CoreGenesis struct {
	NetworkId                string                 `json:"NETWORK_ID"`
	CoreMajorVersion         int                    `json:"CORE_MAJOR_VERSION"`
	FirstEpochStartTimestamp uint64                 `json:"FIRST_EPOCH_START_TIMESTAMP"`
	NetworkParameters        CoreNetworkParameters  `json:"NETWORK_PARAMETERS"`
	Validators               []CoreValidatorStorage `json:"VALIDATORS"`
}
