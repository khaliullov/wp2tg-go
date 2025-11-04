package http

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/khaliullov/wp2tg-go/internal/domain"
	"github.com/khaliullov/wp2tg-go/internal/usecase"
)

//go:embed index.html
var indexHTML string

type SubscriptionHandler struct {
	SubManager  *usecase.SubscriptionManager
	Config      *domain.Config
	ConfigMutex *sync.RWMutex
}

func NewSubscriptionHandler(subManager *usecase.SubscriptionManager, config *domain.Config, configMutex *sync.RWMutex) *SubscriptionHandler {
	return &SubscriptionHandler{
		SubManager:  subManager,
		Config:      config,
		ConfigMutex: configMutex,
	}
}

func (h *SubscriptionHandler) HandleApiSubscriptions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req struct {
			URL string `json:"url"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		host := strings.TrimPrefix(req.URL, "https://")
		host = strings.TrimPrefix(host, "http://")
		host = strings.TrimPrefix(host, "www.")
		host = strings.TrimSuffix(host, "/")
		if host == "" {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		h.ConfigMutex.Lock()
		if _, ok := h.Config.Subscriptions[host]; !ok {
			h.Config.Subscriptions[host] = domain.SubscriptionDetails{}
			_ = h.SubManager.SaveConfigFunc()
		}
		h.ConfigMutex.Unlock()

		if err := h.SubManager.RegisterNewSite(host); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.ConfigMutex.RLock()
		_ = json.NewEncoder(w).Encode(h.Config.Subscriptions[host])
		h.ConfigMutex.RUnlock()
	case http.MethodDelete:
		host := strings.TrimPrefix(r.URL.Path, "/api/subscriptions/")
		host = strings.Trim(host, "/")
		if host == "" {
			http.Error(w, "missing host", http.StatusBadRequest)
			return
		}
		if err := h.SubManager.UnregisterSite(host); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		h.ConfigMutex.RLock()
		_ = json.NewEncoder(w).Encode(h.Config.Subscriptions)
		h.ConfigMutex.RUnlock()
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func StartWebServer(handler *SubscriptionHandler) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(indexHTML))
	})
	http.HandleFunc("/api/subscriptions/", handler.HandleApiSubscriptions)

	addr := fmt.Sprintf(":%d", handler.Config.Main.ListenPort)
	log.Printf("Web UI listening on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
