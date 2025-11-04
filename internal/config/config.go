package config

import (
	"os"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/khaliullov/wp2tg-go/internal/domain"
)

func LoadConfig(configPath string) (*domain.Config, *sync.RWMutex, error) {
	var config domain.Config
	configMutex := &sync.RWMutex{}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configMutex.Lock()
		config.Main.ListenPort = 9090
		config.Main.UserAgent = domain.DefaultUserAgent
		config.Subscriptions = make(map[string]domain.SubscriptionDetails)
		configMutex.Unlock()
		if err := SaveConfig(configPath, &config); err != nil {
			return nil, nil, err
		}
	}

	configMutex.Lock()
	defer configMutex.Unlock()

	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}
	if err := yaml.Unmarshal(b, &config); err != nil {
		return nil, nil, err
	}
	if config.Subscriptions == nil {
		config.Subscriptions = make(map[string]domain.SubscriptionDetails)
	}
	return &config, configMutex, nil
}

func SaveConfig(configPath string, cfg *domain.Config) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, b, 0644)
}
