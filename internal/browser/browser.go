package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"

	"github.com/khaliullov/wp2tg-go/internal/domain"
	"github.com/khaliullov/wp2tg-go/internal/usecase"
)

const (
	ProfileName = "./chrome-profile-%s"
)

type ContextHolder struct {
	BrowserContext playwright.BrowserContext
	CancelCleanup  func()
}

type PlaywrightBrowserLauncher struct {
	Contexts      map[string]*ContextHolder
	ContextsMutex *sync.Mutex
}

func NewPlaywrightBrowserLauncher() *PlaywrightBrowserLauncher {
	return &PlaywrightBrowserLauncher{
		Contexts:      make(map[string]*ContextHolder),
		ContextsMutex: &sync.Mutex{},
	}
}

func (bl *PlaywrightBrowserLauncher) LaunchForSite(sm *usecase.SubscriptionManager, siteURL string) {
	go func() {
		pw, err := playwright.Run()
		if err != nil {
			log.Printf("playwright.Run error: %v", err)
			return
		}

		browserContext, err := bl.newBrowserContext(pw, sm, siteURL)
		if err != nil {
			log.Printf("Failed to create browser context: %v", err)
			return
		}

		ctx := &ContextHolder{
			BrowserContext: browserContext,
		}
		bl.ContextsMutex.Lock()
		bl.Contexts[siteURL] = ctx
		bl.ContextsMutex.Unlock()

		if err := bl.setupRouting(sm, browserContext, siteURL, ctx); err != nil {
			log.Printf("[WSS-Client %s] Route setup failed: %v", siteURL, err)
		}

		page := browserContext.Pages()[0]
		if _, err := page.Goto("http://" + siteURL); err != nil {
			log.Printf("[WSS-Client %s] Goto error: %v", siteURL, err)
		}
	}()
}

func (bl *PlaywrightBrowserLauncher) Cleanup(siteURL string) {
	bl.ContextsMutex.Lock()
	ctx, exists := bl.Contexts[siteURL]
	if exists {
		delete(bl.Contexts, siteURL)
	}
	bl.ContextsMutex.Unlock()

	if exists && ctx != nil {
		go func() {
			if ctx.CancelCleanup != nil {
				ctx.CancelCleanup()
			}
			if ctx.BrowserContext != nil {
				if err := ctx.BrowserContext.Close(); err != nil {
					log.Printf("[Cleanup %s] Browser close error: %v", siteURL, err)
				} else {
					log.Printf("[Cleanup %s] Browser context closed", siteURL)
				}
			}
			userDataDir := fmt.Sprintf(ProfileName, siteURL)
			if err := os.RemoveAll(userDataDir); err != nil {
				log.Printf("[Cleanup %s] Failed to remove user data dir: %v", siteURL, err)
			}
			log.Printf("[Cleanup %s] Cleanup completed", siteURL)
		}()
	}
}

func (bl *PlaywrightBrowserLauncher) newBrowserContext(pw *playwright.Playwright, sm *usecase.SubscriptionManager, siteURL string) (playwright.BrowserContext, error) {
	userDataDir, _ := filepath.Abs(fmt.Sprintf(ProfileName, siteURL))
	_ = os.MkdirAll(userDataDir, 0755)

	ua := sm.Config.Main.UserAgent
	if ua == "" {
		ua = domain.DefaultUserAgent
	}

	contextOptions := playwright.BrowserTypeLaunchPersistentContextOptions{
		Headless:          playwright.Bool(false),
		IgnoreHttpsErrors: playwright.Bool(true),
		Args: []string{
			"--disable-web-security",
			"--disable-features=IsolateOrigins,site-per-process",
			"--allow-running-insecure-content",
			"--disable-blink-features=AutomationControlled",
		},
		UserAgent: playwright.String(ua),
	}

	browserContext, err := pw.Chromium.LaunchPersistentContext(userDataDir, contextOptions)
	if err != nil {
		return nil, fmt.Errorf("Playwright launch error: %w", err)
	}

	scriptContent := strings.ReplaceAll(initScript, "__SITE_HOST__", siteURL)
	if err := browserContext.AddInitScript(playwright.Script{Content: &scriptContent}); err != nil {
		return nil, fmt.Errorf("AddInitScript error: %w", err)
	}

	return browserContext, nil
}

func (bl *PlaywrightBrowserLauncher) setupRouting(sm *usecase.SubscriptionManager, browserContext playwright.BrowserContext, siteURL string, ctx *ContextHolder) error {
	var hook sync.Mutex
	return browserContext.Route("**/*", func(route playwright.Route) {
		req := route.Request()

		if strings.HasSuffix(req.URL(), "/fakeapi/manifest") {
			bl.handleManifestRequest(sm, route, browserContext)
			return
		}

		if strings.HasSuffix(req.URL(), "/fakeapi/capture-vapid") {
			hook.Lock()
			defer hook.Unlock()
			bl.handleCaptureVapidRequest(sm, route, siteURL, ctx)
			return
		}

		route.Continue()
	})
}

func (bl *PlaywrightBrowserLauncher) handleManifestRequest(sm *usecase.SubscriptionManager, route playwright.Route, browserContext playwright.BrowserContext) {
	postData, _ := route.Request().PostData()
	if postData == "" {
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(400), Body: "Empty POST body"})
		return
	}

	var payload struct {
		SiteHost    string `json:"site_host"`
		ManifestURL string `json:"manifest_url"`
	}
	if err := json.Unmarshal([]byte(postData), &payload); err != nil {
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(400), Body: "Invalid JSON"})
		return
	}

	bl.ContextsMutex.Lock()
	_, alreadyRedirected := bl.Contexts[payload.SiteHost+"_manifest_redirected"]
	if alreadyRedirected {
		bl.ContextsMutex.Unlock()
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), Body: "{}"})
		return
	}
	bl.Contexts[payload.SiteHost+"_manifest_redirected"] = nil
	bl.ContextsMutex.Unlock()

	log.Printf("[WSS-Client %s] Manifest detected: %s", payload.SiteHost, payload.ManifestURL)

	page := browserContext.Pages()[0]
	resp, err := page.Goto(payload.ManifestURL)
	if err != nil {
		log.Printf("[WSS-Client %s] Failed to fetch manifest: %v", payload.SiteHost, err)
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), Body: "{}"})
		return
	}

	content, err := resp.Body()
	if err != nil {
		log.Printf("[WSS-Client %s] Failed to read manifest body: %v", payload.SiteHost, err)
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), Body: "{}"})
		return
	}

	var manifest struct {
		StartURL string `json:"start_url"`
	}
	if err := json.Unmarshal(content, &manifest); err != nil {
		log.Printf("[WSS-Client %s] Invalid manifest JSON: %v", payload.SiteHost, err)
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), Body: "{}"})
		return
	}

	if manifest.StartURL == "" {
		log.Printf("[WSS-Client %s] Manifest has no start_url", payload.SiteHost)
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(200), Body: "{}"})
		return
	}

	startURL := resolveURL(payload.ManifestURL, manifest.StartURL)
	log.Printf("[WSS-Client %s] Redirecting to start_url: %s", payload.SiteHost, startURL)

	go func() {
		time.Sleep(500 * time.Millisecond)
		page.Goto(startURL)
	}()

	route.Fulfill(playwright.RouteFulfillOptions{
		Status: playwright.Int(200),
		Body:   `{"redirected": true}`,
	})
}

func (bl *PlaywrightBrowserLauncher) handleCaptureVapidRequest(sm *usecase.SubscriptionManager, route playwright.Route, siteURL string, browserContext *ContextHolder) {
	postData, _ := route.Request().PostData()
	log.Printf("[WSS-Client %s] /fakeapi/capture-vapid POST data: %s", siteURL, postData)

	if postData == "" {
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(400), Body: "Empty POST body"})
		return
	}

	var payload map[string]string
	if err := json.Unmarshal([]byte(postData), &payload); err != nil {
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(400), Body: "Invalid JSON"})
		return
	}

	siteHost, _ := payload["site_host"]
	vapidPub, _ := payload["vapid_public_key"]

	if siteHost == "" || vapidPub == "" {
		route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(400), Body: "site_host and vapid_public_key are required"})
		return
	}

	sm.ConfigMutex.Lock()
	sub, exists := sm.Config.Subscriptions[siteHost]
	if !exists {
		sm.ConfigMutex.Unlock()
		route.Fulfill(playwright.RouteFulfillOptions{
			Status: playwright.Int(400),
			Body:   fmt.Sprintf("Site %s not registered", siteHost),
		})
		return
	}

	log.Printf("[WSS-Client %s]: captured VAPID public key: %s", siteHost, vapidPub)

	var pubKey, authB64, endpoint string
	if sub.P256DH != "" && sub.Endpoint != "" && sub.Auth != "" {
		endpoint = sub.Endpoint
		authB64 = sub.Auth
		pubKey = sub.P256DH
		log.Printf("[WSS-Client %s] Registration cached: %s", siteURL, endpoint)
		sm.ConfigMutex.Unlock()
	} else {
		var privKey string
		pubKey, privKey, _ = usecase.GenerateVAPIDKeys()
		auth := make([]byte, 16)
		usecase.RandRead(auth)
		authB64 = base64.RawURLEncoding.EncodeToString(auth)

		sub.VAPIDPublic = vapidPub
		sub.P256DH = pubKey
		sub.Auth = authB64
		sub.VAPIDPrivate = privKey
		sm.Config.Subscriptions[siteURL] = sub
		_ = sm.SaveConfigFunc()
		sm.ConfigMutex.Unlock()

		done := make(chan string, 1)
		sm.PendingRegister[siteURL] = done

		go func() {
			if err := sm.RegisterWithKey(siteURL, vapidPub); err != nil {
				log.Printf("[WSS-Client %s] Registration failed: %v", siteURL, err)
				done <- ""
			}
		}()

		select {
		case endpoint = <-done:
			if endpoint == "" {
				route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: "Registration failed"})
				return
			}
			log.Printf("[WSS-Client %s] Registration success: %s", siteURL, endpoint)
		case <-time.After(10 * time.Second):
			delete(sm.PendingRegister, siteURL)
			route.Fulfill(playwright.RouteFulfillOptions{Status: playwright.Int(500), Body: "Registration timeout"})
			return
		}
	}

	fakeSubJSON, _ := json.Marshal(map[string]interface{}{
		"endpoint": endpoint,
		"keys": map[string]string{
			"p256dh": pubKey,
			"auth":   authB64,
		},
	})

	route.Fulfill(playwright.RouteFulfillOptions{
		Status:      playwright.Int(200),
		Body:        string(fakeSubJSON),
		ContentType: playwright.String("application/json"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	browserContext.CancelCleanup = cancel

	go func() {
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			log.Printf("[Cleanup %s] Auto-cleanup cancelled", siteURL)
			return
		}

		bl.Cleanup(siteURL)
	}()
}

func resolveURL(base, ref string) string {
	u, err := url.Parse(ref)
	if err == nil && u.IsAbs() {
		return ref
	}
	if baseU, err := url.Parse(base); err == nil {
		baseU.Path = u.Path
		baseU.RawQuery = u.RawQuery
		return baseU.String()
	}
	return ref
}
