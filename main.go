package main

import (
	"flag"
	"log"

	"github.com/playwright-community/playwright-go"

	"github.com/khaliullov/wp2tg-go/internal/browser"
	"github.com/khaliullov/wp2tg-go/internal/config"
	delivery "github.com/khaliullov/wp2tg-go/internal/delivery/http"
	"github.com/khaliullov/wp2tg-go/internal/telegram"
	"github.com/khaliullov/wp2tg-go/internal/usecase"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the configuration file")
	skipPlaywrightInstall := flag.Bool("skip-playwright-install", false, "Skip Playwright installation")
	flag.Parse()

	cfg, cfgMutex, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("loadConfig error: %v", err)
	}

	telegramBot, err := telegram.InitTelegram(cfg)
	if err != nil {
		log.Fatalf("telegram init error: %v", err)
	}

	if !*skipPlaywrightInstall {
		if err := playwright.Install(); err != nil {
			log.Fatalf("playwright install error: %v", err)
		}
	}

	browserLauncher := browser.NewPlaywrightBrowserLauncher()

	subManager := usecase.NewSubscriptionManager(cfg, cfgMutex, telegramBot, func() error {
		return config.SaveConfig(*configPath, cfg)
	}, browserLauncher)

	cfgMutex.RLock()
	for host, sd := range cfg.Subscriptions {
		if sd.ChannelID != "" {
			subManager.Registered[sd.ChannelID] = host
			log.Printf("Restored channel mapping %s -> %s", sd.ChannelID, host)
		}
	}
	cfgMutex.RUnlock()

	subManager.Start()

	subscriptionHandler := delivery.NewSubscriptionHandler(subManager, cfg, cfgMutex)
	delivery.StartWebServer(subscriptionHandler)
}
