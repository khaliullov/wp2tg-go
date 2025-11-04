package domain

const (
	DefaultUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
)

type SubscriptionDetails struct {
	Endpoint              string `yaml:"endpoint,omitempty" json:"-"`
	P256DH                string `yaml:"p256dh,omitempty" json:"-"`
	Auth                  string `yaml:"auth,omitempty" json:"-"`
	VAPIDPublic           string `yaml:"vapid_public,omitempty" json:"-"` // real server's key
	VAPIDPrivate          string `yaml:"vapid_private,omitempty" json:"-"`
	ChannelID             string `yaml:"channel_id,omitempty" json:"-"`
	TelegramChatID        int64  `yaml:"telegram_chat_id,omitempty" json:"telegram_chat_id,omitempty"`
	AutoCloseDelaySeconds *int   `yaml:"auto_close_delay_seconds,omitempty" json:"auto_close_delay_seconds"`
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
