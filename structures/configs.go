package structures

type NodeLevelConfig struct {
	PublicKey             string            `json:"PUBLIC_KEY"`
	PrivateKey            string            `json:"PRIVATE_KEY"`
	ExtraDataToBlock      map[string]string `json:"EXTRA_DATA_TO_BLOCK"`
	Interface             string            `json:"INTERFACE"`
	Port                  int               `json:"PORT"`
	WebSocketInterface    string            `json:"WEBSOCKET_INTERFACE"`
	WebSocketPort         int               `json:"WEBSOCKET_PORT"`
	PointOfDistributionWS string            `json:"POINT_OF_DISTRIBUTION"`
	DisablePoDOutbox      bool              `json:"DISABLE_POD_OUTBOX"`

	// CoreBootstrapNodes is the list of HTTP endpoints of modulr-core nodes that
	// the anchor can use to resolve information about the core network at runtime.
	// Currently used to discover WSS endpoints of core validators via the
	// `GET /get_validator_ws_endpoints?pubkeys=...` route when collecting ALFPs
	// from a core quorum that includes validators not present in CORE_GENESIS.
	//
	// Each entry must be a fully-qualified HTTP(S) URL without trailing slash,
	// e.g. "http://node1.example:8080".
	CoreBootstrapNodes []string `json:"CORE_BOOTSTRAP_NODES"`
}
