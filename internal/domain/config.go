package domain

const (
	DefaultUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
)

type SubscriptionDetails struct {
	Endpoint       string `yaml:"endpoint,omitempty"`
	P256DH         string `yaml:"p256dh,omitempty"`
	Auth           string `yaml:"auth,omitempty"`
	VAPIDPublic    string `yaml:"vapid_public,omitempty"` // real server's key
	VAPIDPrivate   string `yaml:"vapid_private,omitempty"`
	ChannelID      string `yaml:"channel_id,omitempty"`
	CapturedVAPID  bool   `yaml:"captured_vapid,omitempty"` // optional flag
	TelegramChatID int64  `yaml:"telegram_chat_id,omitempty"`
}

type Config struct {
	Main struct {
		TelegramToken  string `yaml:"telegram_token"`
		TelegramChatID int64  `yaml:"telegram_chat_id"`
		ListenPort     int    `yaml:"listen_port"`
		UAID           string `yaml:"uaid,omitempty"`
		UserAgent      string `yaml:"user_agent"`
	} `yaml:"main"`
	Subscriptions map[string]SubscriptionDetails `yaml:"subscriptions"`
}
