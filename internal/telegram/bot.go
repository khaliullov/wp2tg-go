package telegram

import (
	"fmt"
	"log"
	"time"

	"gopkg.in/telebot.v3"

	"github.com/khaliullov/wp2tg-go/internal/domain"
)

func InitTelegram(config *domain.Config) (*telebot.Bot, error) {
	if config.Main.TelegramToken == "" || config.Main.TelegramChatID == 0 {
		return nil, fmt.Errorf("telegram_token and telegram_chat_id must be set in config.yaml")
	}
	b, err := telebot.NewBot(telebot.Settings{
		Token:  config.Main.TelegramToken,
		Poller: &telebot.LongPoller{Timeout: 10 * time.Second},
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Telegram bot initialized")
	return b, nil
}
