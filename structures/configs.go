package structures

type NodeLevelConfig struct {
	PublicKey          string            `json:"PUBLIC_KEY"`
	PrivateKey         string            `json:"PRIVATE_KEY"`
	ExtraDataToBlock   map[string]string `json:"EXTRA_DATA_TO_BLOCK"`
	Interface          string            `json:"INTERFACE"`
	Port               int               `json:"PORT"`
	WebSocketInterface string            `json:"WEBSOCKET_INTERFACE"`
	WebSocketPort      int               `json:"WEBSOCKET_PORT"`
}
