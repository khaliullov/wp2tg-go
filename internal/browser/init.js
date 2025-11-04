(function() {
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', sendManifestIfAny);
	} else {
		sendManifestIfAny();
	}
	
	function sendManifestIfAny() {
		const manifestLink = document.querySelector('link[rel="manifest"]');
		if (manifestLink && manifestLink.href) {
		    console.log('[wp2tg] found manifest', manifestLink.href);
			fetch('/fakeapi/manifest', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					site_host: '__SITE_HOST__',
					manifest_url: manifestLink.href
				})
			}).catch(e => console.warn('[wp2tg] Failed to send manifest info:', e));
		}
	}

    const originalMatchMedia = window.matchMedia;
    window.matchMedia = function(query) {
        if (query === '(display-mode: standalone)' || query === '(display-mode: fullscreen)') {
            return {
                matches: true,
                media: query,
                onchange: null,
                addListener: () => {},
                removeListener: () => {}
            };
        }
        return originalMatchMedia.apply(this, arguments);
    };

    try {
        Object.defineProperty(navigator, 'standalone', {
            value: true,
            configurable: false,
            writable: false
        });
    } catch (e) {}

    console.log('[wp2tg] Enabled display-mode standalone');

    console.log('[wp2tg] Installing PushManager.subscribe() hook...');
    const originalSubscribe = PushManager.prototype.subscribe;

    PushManager.prototype.subscribe = async function(options) {
        try {
            let capturedKey = null;
            console.log('[wp2tg] PushManager.subscribe() called', options);
            if (options && options.applicationServerKey) {
                let key = options.applicationServerKey;
                console.log('[wp2tg] raw applicationServerKey type:', typeof key, key.constructor?.name, key);

                if (typeof key === 'string') {
                    if (key.trim() !== '') {
                        capturedKey = key;
                        console.log('[wp2tg] Captured applicationServerKey (string):', capturedKey);
                    }
                } else if (key instanceof ArrayBuffer || ArrayBuffer.isView(key)) {
                    const bytes = new Uint8Array(key.buffer || key);
                    const bin = String.fromCharCode.apply(null, bytes);
                    const base64 = btoa(bin);
                    capturedKey = base64
                        .replace(/\+/g, '-')
                        .replace(/\//g, '_')
                        .replace(/=+$/, '');
                    console.log('[wp2tg] Captured applicationServerKey (binary):', capturedKey);
                } else {
                    console.warn('[wp2tg] Unsupported applicationServerKey type:', typeof key);
                }
            } else {
                console.log('[wp2tg] subscribe() called without applicationServerKey');
            }

            const fakeSubResponse = await fetch('/fakeapi/capture-vapid', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    site_host: '__SITE_HOST__',
                    vapid_public_key: capturedKey
                })
            });

            if (!fakeSubResponse.ok) {
                console.error('[wp2tg] /fakeapi/capture-vapid failed:', fakeSubResponse.status);
                return await originalSubscribe.apply(this, arguments);
            }

            const fakeSub = await fakeSubResponse.json();
            console.log('[wp2tg] Received fake subscription:', fakeSub);

            const fakeSubscription = {
                endpoint: fakeSub.endpoint,
                expirationTime: null,
                options: {
                    userVisibleOnly: true,
                    applicationServerKey: options?.applicationServerKey || null
                },
                getKey: function(name) {
                    console.log('[wp2tg] fake subscription getKey:', name);
                    if (name === 'p256dh' || name === 'auth') {
                        const b64url = fakeSub.keys[name];
                        if (!b64url) {
                            console.log('[wp2tg] fake subscription empty value for getKey:', name);
                            return null;
                        }
                        let s = b64url;
                        while (s.length % 4) s += '=';
                        const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
                        const bin = atob(b64);
                        return new Uint8Array(bin.split('').map(c => c.charCodeAt(0))).buffer;
                    }
                    return null;
                },
                toJSON: function() {
                    return {
                        endpoint: this.endpoint,
                        keys: fakeSub.keys
                    };
                }
            };

            Object.setPrototypeOf(fakeSubscription, PushSubscription.prototype);
            console.log('[wp2tg] Returning fake PushSubscription with endpoint:', fakeSub.endpoint);
            return fakeSubscription;

        } catch (err) {
            console.error('[wp2tg] Error in subscribe hook:', err);
            return await originalSubscribe.apply(this, arguments);
        }
    };

    console.log('[wp2tg] PushManager.subscribe() hook installed successfully');
})();
