package usecase

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/xakep666/ecego"
	"gopkg.in/telebot.v3"

	"github.com/khaliullov/wp2tg-go/internal/domain"
)

type BrowserLauncher interface {
	LaunchForSite(sm *SubscriptionManager, siteURL string)
	Cleanup(sm *SubscriptionManager, siteURL string)
}

type SubscriptionManager struct {
	conn            *websocket.Conn
	mutex           sync.Mutex
	pending         map[string]string // channelID -> siteHost awaiting register response
	Registered      map[string]string // channelID -> siteHost
	stopChan        chan struct{}
	PendingRegister map[string]chan string // siteHost -> chan endpoint
	PendingMutex    sync.Mutex

	// Dependencies
	Config          *domain.Config
	ConfigMutex     *sync.RWMutex
	TelegramBot     *telebot.Bot
	SaveConfigFunc  func() error
	BrowserLauncher BrowserLauncher
}

func NewSubscriptionManager(
	cfg *domain.Config,
	cfgMutex *sync.RWMutex,
	bot *telebot.Bot,
	saveConfigFunc func() error,
	browserLauncher BrowserLauncher,
) *SubscriptionManager {
	return &SubscriptionManager{
		pending:         make(map[string]string),
		Registered:      make(map[string]string),
		PendingRegister: make(map[string]chan string),
		stopChan:        make(chan struct{}),
		Config:          cfg,
		ConfigMutex:     cfgMutex,
		TelegramBot:     bot,
		SaveConfigFunc:  saveConfigFunc,
		BrowserLauncher: browserLauncher,
	}
}

func (sm *SubscriptionManager) readLoop() {
	defer func() {
		sm.mutex.Lock()
		if sm.conn != nil {
			_ = sm.conn.Close()
			sm.conn = nil
		}
		sm.mutex.Unlock()
	}()

	for {
		select {
		case <-sm.stopChan:
			return
		default:
			if sm.conn == nil {
				return
			}
			_, msgBytes, err := sm.conn.ReadMessage()
			if err != nil {
				log.Printf("[WSS-Client] read error: %v", err)
				return
			}

			var mt struct {
				MessageType string `json:"messageType"`
				Uaid        string `json:"uaid,omitempty"`
			}
			_ = json.Unmarshal(msgBytes, &mt)
			log.Printf("[WSS-Client] Mozilla ->: %s", string(msgBytes))

			var generic map[string]interface{}
			if err := json.Unmarshal(msgBytes, &generic); err == nil {
				if mt.MessageType == "hello" {
					if uaidRaw, ok := generic["uaid"].(string); ok && uaidRaw != "" {
						sm.ConfigMutex.Lock()
						if sm.Config.Main.UAID != uaidRaw {
							sm.Config.Main.UAID = uaidRaw
							_ = sm.SaveConfigFunc()
							log.Printf("[WSS-Client] Saved UAID to config.yaml: %s", uaidRaw)
						}
						sm.ConfigMutex.Unlock()
					}
				}
			}

			var typeCheck struct {
				MessageType string `json:"messageType"`
			}
			if err := json.Unmarshal(msgBytes, &typeCheck); err != nil {
				continue
			}
			switch typeCheck.MessageType {
			case string(domain.MessageTypeRegister):
				var rr domain.RegisterResponse
				if err := json.Unmarshal(msgBytes, &rr); err == nil {
					sm.handleRegisterResponse(rr)
				}
			case "notification":
				var nm domain.NotificationMessage
				if err := json.Unmarshal(msgBytes, &nm); err == nil {
					sm.handleNotification(nm)
				}
			}
		}
	}
}

func (sm *SubscriptionManager) handleRegisterResponse(resp domain.RegisterResponse) {
	sm.mutex.Lock()
	siteHost, ok := sm.pending[resp.ChannelID]
	if ok {
		delete(sm.pending, resp.ChannelID)
		sm.Registered[resp.ChannelID] = siteHost
	}
	sm.mutex.Unlock()

	if !ok {
		log.Printf("[WSS-Client] register response for unknown channel: %s", resp.ChannelID)
		return
	}

	if resp.Status != 200 {
		log.Printf("[WSS-Client %s] register failed status=%d", siteHost, resp.Status)
		sm.PendingMutex.Lock()
		if ch, exists := sm.PendingRegister[siteHost]; exists {
			delete(sm.PendingRegister, siteHost)
			ch <- ""
		}
		sm.PendingMutex.Unlock()
		return
	}

	log.Printf("[WSS-Client %s] registered endpoint=%s", siteHost, resp.PushEndpoint)

	sm.ConfigMutex.Lock()
	sub := sm.Config.Subscriptions[siteHost]
	sub.Endpoint = resp.PushEndpoint
	sub.ChannelID = resp.ChannelID
	sm.Config.Subscriptions[siteHost] = sub
	_ = sm.SaveConfigFunc()
	sm.ConfigMutex.Unlock()

	sm.PendingMutex.Lock()
	if ch, exists := sm.PendingRegister[siteHost]; exists {
		delete(sm.PendingRegister, siteHost)
		ch <- resp.PushEndpoint
	}
	sm.PendingMutex.Unlock()
}

func (sm *SubscriptionManager) handleNotification(notif domain.NotificationMessage) {
	sm.mutex.Lock()
	siteHost, ok := sm.Registered[notif.ChannelID]
	sm.mutex.Unlock()
	if !ok {
		log.Printf("[WSS-Client] notification for unknown channel: %s. Unsubscribing", notif.ChannelID)
		sm.ack(notif.ChannelID, notif.Version)
		sm.unregisterSite("<unknown>", notif.ChannelID)
		return
	}

	sm.ConfigMutex.RLock()
	sd, exists := sm.Config.Subscriptions[siteHost]
	sm.ConfigMutex.RUnlock()
	if !exists {
		log.Printf("[WSS-Client %s] no subscription details found", siteHost)
		return
	}

	cipher, err := decodeBase64URL(notif.Data)
	if err != nil {
		log.Printf("[WSS-Client %s] decode data error: %v (using raw bytes)", siteHost, err)
		cipher = []byte(notif.Data)
	}

	var saltBytes, dhBytes []byte
	if ck, ok := notif.Headers["crypto_key"]; ok && ck != "" {
		parts := strings.FieldsFunc(ck, func(r rune) bool { return r == ';' || r == ',' })
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "dh=") {
				raw := strings.TrimPrefix(p, "dh=")
				if b, e := decodeBase64URL(raw); e == nil {
					dhBytes = b
				}
			}
		}
	}

	if enc, ok := notif.Headers["encryption"]; ok && enc != "" {
		parts := strings.FieldsFunc(enc, func(r rune) bool { return r == ';' || r == ',' })
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, "salt=") {
				raw := strings.TrimPrefix(p, "salt=")
				if b, e := decodeBase64URL(raw); e == nil {
					saltBytes = b
				}
			}
		}
	}

	decrypted := "[decryption failed]"
	decryptedOK := false

	if sd.VAPIDPrivate != "" && sd.Auth != "" {
		authBytes, abErr := decodeBase64URL(sd.Auth)
		if abErr == nil {
			priv, pkErr := privateKeyFromRaw(sd.VAPIDPrivate)
			if pkErr == nil {
				engine := ecego.NewEngine(ecego.SingleKey(priv), ecego.WithAuthSecret(authBytes))
				params := ecego.OperationalParams{Version: ecego.AES128GCM}
				if ver, ok := notif.Headers["encoding"]; ok && ver != "" {
					params.Version = ecego.Version(ver)
				}
				if len(saltBytes) > 0 {
					params.Salt = saltBytes
				}
				if len(dhBytes) > 0 {
					params.DH = dhBytes
				}
				plain, err := engine.Decrypt(cipher, nil, params)
				if err == nil {
					if utf8.Valid(plain) {
						decrypted = string(plain)
					} else {
						decrypted = fmt.Sprintf("[binary] hex=%x", plain)
					}
					decryptedOK = true
				}
			}
		}
	}

	var prettyPayload string
	if decryptedOK && decrypted != "" {
		if raw := []byte(decrypted); len(raw) > 0 && raw[0] == '{' {
			var prettyBuf bytes.Buffer
			if err := json.Indent(&prettyBuf, raw, "", "  "); err == nil {
				prettyPayload = prettyBuf.String()
			} else {
				prettyPayload = decrypted
			}
		} else {
			prettyPayload = decrypted
		}
	} else {
		prettyPayload = decrypted
	}
	log.Printf("[WSS-Client %s] notification version=%s decrypted=%v payload=\n%s", siteHost, notif.Version, decryptedOK, prettyPayload)

	if sm.TelegramBot != nil {
		var title, body string
		if decryptedOK && decrypted != "" && decrypted[0] == '{' {
			var fcmPayload struct {
				Notification struct {
					Title string `json:"title"`
					Body  string `json:"body"`
				} `json:"notification"`
			}
			if json.Unmarshal([]byte(decrypted), &fcmPayload) == nil {
				title = fcmPayload.Notification.Title
				body = fcmPayload.Notification.Body
			}
		}
		msg := fmt.Sprintf("🔔 *%s*\n*%s*\n%s", siteHost, title, body)
		tcid := sm.Config.Main.TelegramChatID
		if sd.TelegramChatID != 0 {
			tcid = sd.TelegramChatID
		}
		_, _ = sm.TelegramBot.Send(&telebot.Chat{ID: tcid}, msg, telebot.ModeMarkdown)
	}

	sm.ack(notif.ChannelID, notif.Version)
}

func (sm *SubscriptionManager) ack(channelID, version string) {
	ack := domain.AckMessage{
		MessageType: "ack",
		Updates:     []domain.AckUpdate{{ChannelID: channelID, Version: version}},
	}
	sm.mutex.Lock()
	if sm.conn != nil {
		_ = sm.conn.WriteJSON(ack)
	}
	sm.mutex.Unlock()
}

func (sm *SubscriptionManager) RegisterNewSite(siteURL string) error {
	sm.ConfigMutex.Lock()
	if _, exists := sm.Config.Subscriptions[siteURL]; !exists {
		sm.Config.Subscriptions[siteURL] = domain.SubscriptionDetails{}
		_ = sm.SaveConfigFunc()
	}
	sm.ConfigMutex.Unlock()
	log.Printf("[WSS-Client %s] Placeholder created. Awaiting VAPID key via /fakeapi/capture-vapid", siteURL)

	go sm.BrowserLauncher.LaunchForSite(sm, siteURL)

	return nil
}

func (sm *SubscriptionManager) RegisterWithKey(siteHost, realVAPIDPub string) error {
	sm.mutex.Lock()
	if sm.conn == nil {
		sm.mutex.Unlock()
		return fmt.Errorf("no WSS connection")
	}
	sm.mutex.Unlock()

	sm.ConfigMutex.RLock()
	_, exists := sm.Config.Subscriptions[siteHost]
	sm.ConfigMutex.RUnlock()
	if !exists {
		return fmt.Errorf("no subscription for %s", siteHost)
	}

	channelID := uuid.New().String()
	reg := domain.RegisterMessage{
		MessageType: string(domain.MessageTypeRegister),
		ChannelID:   channelID,
		Key:         realVAPIDPub,
	}

	sm.mutex.Lock()
	sm.pending[channelID] = siteHost
	sm.mutex.Unlock()

	if err := sm.conn.WriteJSON(reg); err != nil {
		sm.mutex.Lock()
		delete(sm.pending, channelID)
		sm.mutex.Unlock()
		return fmt.Errorf("register write failed: %w", err)
	}

	sm.ConfigMutex.Lock()
	sub := sm.Config.Subscriptions[siteHost]
	sub.ChannelID = channelID
	sm.Config.Subscriptions[siteHost] = sub
	_ = sm.SaveConfigFunc()
	sm.ConfigMutex.Unlock()

	log.Printf("[WSS-Client %s] Registering with real VAPID key: %s", siteHost, realVAPIDPub)
	return nil
}

func (sm *SubscriptionManager) unregisterSite(siteHost string, channelID string) {
	msg := map[string]interface{}{
		"messageType": string(domain.MessageTypeUnregister),
		"channelID":   channelID,
	}
	sm.mutex.Lock()
	if sm.conn != nil {
		if err := sm.conn.WriteJSON(msg); err != nil {
			log.Printf("[WSS-Client %s] Unregister send failed: %v", siteHost, err)
		}
	}
	sm.mutex.Unlock()
}

func (sm *SubscriptionManager) UnregisterSite(siteHost string) error {
	sm.ConfigMutex.RLock()
	sub, exists := sm.Config.Subscriptions[siteHost]
	sm.ConfigMutex.RUnlock()

	if exists && sub.ChannelID != "" {
		sm.unregisterSite(siteHost, sub.ChannelID)
	}

	sm.cleanupSiteData(siteHost)

	sm.ConfigMutex.Lock()
	delete(sm.Config.Subscriptions, siteHost)
	_ = sm.SaveConfigFunc()
	sm.ConfigMutex.Unlock()

	sm.BrowserLauncher.Cleanup(sm, siteHost)

	log.Printf("[WSS-Client %s] Unregister processed and cleanup triggered", siteHost)
	return nil
}

func (sm *SubscriptionManager) FreeSite(siteHost string) error {
	log.Printf("[WSS-Client %s] Freeing site and cleaning up browser", siteHost)
	sm.cleanupSiteData(siteHost)
	sm.BrowserLauncher.Cleanup(sm, siteHost)
	return nil
}

func (sm *SubscriptionManager) cleanupSiteData(siteHost string) {
	var ch chan string
	sm.PendingMutex.Lock()
	if c, ok := sm.PendingRegister[siteHost]; ok {
		delete(sm.PendingRegister, siteHost)
		ch = c
	}
	sm.PendingMutex.Unlock()

	if ch != nil {
		select {
		case ch <- "": // Signal cancellation
		default:
			log.Printf("[WSS-Client %s] cleanupSiteData: could not send cancellation signal to pending registration.", siteHost)
		}
	}

	sm.ConfigMutex.RLock()
	sub, exists := sm.Config.Subscriptions[siteHost]
	sm.ConfigMutex.RUnlock()

	if exists && sub.ChannelID != "" {
		sm.mutex.Lock()
		delete(sm.pending, sub.ChannelID)
		if sub.VAPIDPublic == "" || sub.VAPIDPrivate == "" || sub.Endpoint == "" {
			delete(sm.Registered, sub.ChannelID)
		}
		sm.mutex.Unlock()
	}
}

func (sm *SubscriptionManager) dial() error {
	u := url.URL{Scheme: "wss", Host: "push.services.mozilla.com", Path: "/"}
	conn, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial push service: %w", err)
	}
	conn.SetPongHandler(func(appData string) error { return nil })
	sm.conn = conn
	return nil
}

func (sm *SubscriptionManager) keepAliveLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.mutex.Lock()
			if sm.conn == nil {
				sm.mutex.Unlock()
				return
			}
			keepAliveMsg := map[string]interface{}{}
			err := sm.conn.WriteJSON(keepAliveMsg)
			sm.mutex.Unlock()
			if err != nil {
				return
			}
		case <-sm.stopChan:
			return
		}
	}
}

func (sm *SubscriptionManager) Start() {
	go func() {
		for {
			select {
			case <-sm.stopChan:
				sm.closeConn()
				return
			default:
			}

			if err := sm.dial(); err != nil {
				time.Sleep(5 * time.Second)
				continue
			}

			if err := sm.sendHello(); err != nil {
				sm.closeConn()
				time.Sleep(5 * time.Second)
				continue
			}

			keepAliveDone := make(chan struct{})
			go func() {
				defer close(keepAliveDone)
				sm.keepAliveLoop()
			}()

			sm.readLoopOnce()

			close(sm.stopChan)
			<-keepAliveDone
			sm.stopChan = make(chan struct{})

			log.Println("[WSS-Client] Connection lost. Reconnecting in 5s...")
			sm.closeConn()
			time.Sleep(5 * time.Second)
		}
	}()
}

func (sm *SubscriptionManager) closeConn() {
	sm.mutex.Lock()
	if sm.conn != nil {
		_ = sm.conn.Close()
		sm.conn = nil
	}
	sm.mutex.Unlock()
}

func (sm *SubscriptionManager) sendHello() error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	if sm.conn == nil {
		return fmt.Errorf("no connection")
	}

	var channelIDs []string
	sm.ConfigMutex.RLock()
	for _, sub := range sm.Config.Subscriptions {
		if sub.ChannelID != "" {
			channelIDs = append(channelIDs, sub.ChannelID)
		}
	}
	uaid := sm.Config.Main.UAID
	sm.ConfigMutex.RUnlock()

	hello := domain.HelloRequest{
		Type:       domain.MessageTypeHello,
		UseWebPush: true,
	}
	if uaid != "" {
		hello.UAID = uaid
		hello.ChannelIDs = channelIDs
	}

	return sm.conn.WriteJSON(hello)
}

func (sm *SubscriptionManager) readLoopOnce() {
	for {
		if sm.conn == nil {
			return
		}
		_, msgBytes, err := sm.conn.ReadMessage()
		if err != nil {
			return
		}

		var typeCheck struct {
			MessageType string `json:"messageType"`
		}
		if json.Unmarshal(msgBytes, &typeCheck) != nil {
			continue
		}

		log.Printf("[WSS-Client] Mozilla ->: %s", string(msgBytes))

		switch typeCheck.MessageType {
		case "hello":
			var resp domain.HelloResponse
			if json.Unmarshal(msgBytes, &resp) == nil && resp.UAID != "" {
				sm.ConfigMutex.Lock()
				if sm.Config.Main.UAID != resp.UAID {
					sm.Config.Main.UAID = resp.UAID
					_ = sm.SaveConfigFunc()
					log.Printf("[WSS-Client] Saved UAID: %s", resp.UAID)
				}
				sm.ConfigMutex.Unlock()
			}
		case string(domain.MessageTypeRegister):
			var rr domain.RegisterResponse
			if json.Unmarshal(msgBytes, &rr) == nil {
				sm.handleRegisterResponse(rr)
			}
		case "notification":
			var nm domain.NotificationMessage
			if json.Unmarshal(msgBytes, &nm) == nil {
				sm.handleNotification(nm)
			}
		}
	}
}

func privateKeyFromRaw(privRawB64 string) (*ecdsa.PrivateKey, error) {
	privRaw, err := decodeBase64URL(privRawB64)
	if err != nil {
		return nil, err
	}
	if len(privRaw) != 32 {
		return nil, fmt.Errorf("invalid priv length: %d", len(privRaw))
	}
	curve := elliptic.P256()
	d := new(big.Int).SetBytes(privRaw)
	x, y := curve.ScalarBaseMult(privRaw)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y},
		D:         d,
	}, nil
}

func GenerateVAPIDKeys() (string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	pubBytes := elliptic.Marshal(priv.Curve, priv.PublicKey.X, priv.PublicKey.Y)
	publicKey := base64.RawURLEncoding.EncodeToString(pubBytes)
	dBytes := priv.D.Bytes()
	paddedD := make([]byte, 32)
	copy(paddedD[32-len(dBytes):], dBytes)
	privateKey := base64.RawURLEncoding.EncodeToString(paddedD)
	return publicKey, privateKey, nil
}

func RandRead(b []byte) (int, error) {
	return rand.Read(b)
}

func decodeBase64URL(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
