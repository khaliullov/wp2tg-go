package domain

type MessageType string

const (
	MessageTypeHello      MessageType = "hello"
	MessageTypeRegister   MessageType = "register"
	MessageTypeUnregister MessageType = "unregister"
)

type HelloRequest struct {
	Type       MessageType `json:"messageType"`
	UAID       string      `json:"uaid,omitempty"`
	ChannelIDs []string    `json:"channelIDs,omitempty"`
	UseWebPush bool        `json:"use_webpush,omitempty"`
}

type HelloResponse struct {
	MessageType string            `json:"messageType"`
	UAID        string            `json:"uaid"`
	Status      int               `json:"status"`
	UseWebPush  bool              `json:"use_webpush"`
	Broadcasts  map[string]string `json:"broadcasts,omitempty"`
}

type RegisterMessage struct {
	MessageType string `json:"messageType"`
	ChannelID   string `json:"channelID"`
	Key         string `json:"key"` // VAPID Public Key
}

type RegisterResponse struct {
	MessageType  string `json:"messageType"`
	ChannelID    string `json:"channelID"`
	Status       int    `json:"status"`
	PushEndpoint string `json:"pushEndpoint"`
}

type NotificationMessage struct {
	MessageType string            `json:"messageType"`
	ChannelID   string            `json:"channelID"`
	Version     string            `json:"version"`
	Data        string            `json:"data"`
	Headers     map[string]string `json:"headers"`
}

type AckMessage struct {
	MessageType string      `json:"messageType"`
	Updates     []AckUpdate `json:"updates"`
}

type AckUpdate struct {
	ChannelID string `json:"channelID"`
	Version   string `json:"version"`
}
