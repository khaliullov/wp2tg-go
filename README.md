# WP2TG: Web Push to Telegram Gateway

WP2TG is a gateway that captures web push notifications and forwards them to a Telegram chat. It acts as a client for websites that use VAPID-based web push, allowing you to receive notifications on Telegram without needing a traditional browser.

## Features

- **Web Push Subscription**: Manages subscriptions to websites using the Web Push protocol.
- **Telegram Forwarding**: Forwards captured notifications to a configurable Telegram chat.
- **Playwright Integration**: Uses Playwright to automate browser interactions for subscribing to sites that require it.
- **Self-Contained**: Embeds all necessary assets (HTML, JavaScript) into a single binary, making it easy to deploy.
- **Configurable**: Supports command-line flags for setting the configuration path and skipping Playwright installation.

## How It Works

1.  **Subscription**: When you add a new site, WP2TG launches a Playwright-controlled browser to navigate the site and trigger the push subscription process.
2.  **VAPID Key Capture**: An injected JavaScript hook intercepts the `PushManager.subscribe()` call to capture the site's VAPID public key.
3.  **Fake Subscription**: WP2TG generates its own key pair and returns a fake `PushSubscription` object to the site, with an endpoint pointing back to itself.
4.  **Notification Forwarding**: When the site sends a push notification, WP2TG receives it, decrypts the payload, and forwards it to your configured Telegram chat.

## Getting Started

### Prerequisites

- Go 1.18 or higher
- A Telegram bot token and chat ID

### Build

To build the application, run the following command:

```sh
go build -o wp2tg main.go
```

### Configuration

Create a `config.yaml` file with the following structure:

```yaml
main:
  telegram_token: "YOUR_TELEGRAM_BOT_TOKEN"
  telegram_chat_id: YOUR_TELEGRAM_CHAT_ID
  listen_port: 9090
  uaid: ""
  user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
subscriptions: {}
```

### Run

By default, the application will look for `config.yaml` in the current directory. You can specify a different path using the `--config` flag:

```sh
./wp2tg --config /path/to/your/config.yaml
```

The application will automatically download and install the required Playwright browser dependencies on the first run. To skip this, use the `--skip-playwright-install` flag:

```sh
./wp2tg --skip-playwright-install
```

## Project Structure

The project follows the Clean Architecture pattern to separate concerns and improve maintainability:

-   **/cmd**: Main application entry point.
-   **/internal/browser**: Handles Playwright browser automation and request interception.
-   **/internal/config**: Manages loading and saving the application configuration.
-   **/internal/delivery/http**: Provides the web UI and API for managing subscriptions.
-   **/internal/domain**: Contains the core domain models and constants.
-   **/internal/telegram**: Manages the Telegram bot and notification forwarding.
-   **/internal/usecase**: Implements the core business logic for subscription management.
