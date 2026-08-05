// helper.js - Cloudflare Turnstile Token Provider for 3rb.io (FIXED INVISIBLE VERSION)
window._3rbCaptchaQueue = [];
window._3rbCaptchaBusy  = false;
window._3rbTokenReady   = false;
window._3rbToken        = null;
window._3rbCaptchaSolved = false;

function buildCaptchaPacket(token) {
    // Matches the ORIGINAL 3rb.io client exactly:
    // opcode 123 (0x7b) + 0x06 sub-type byte + raw UTF-8 token + trailing null byte (0x00)
    const bytes = new TextEncoder().encode(token);
    const buf = new ArrayBuffer(2 + bytes.length + 1); // +1 for trailing null byte
    const u8 = new Uint8Array(buf);
    u8[0] = 123; // 0x7b — captcha token opcode
    u8[1] = 6;   // 0x06 — constant sub-type byte from the original client
    u8.set(bytes, 2);
    u8[2 + bytes.length] = 0; // null terminator
    return buf;
}
window._3rbBuildCaptchaPacket = buildCaptchaPacket;

let _tsLoaded = false;
let _activeWidgets = {};

function getTurnstileContainer(label) {
    const isTab2 = (label === 'ws2' || label === 'secondary');
    const targetId = isTab2 ? 'cf-turnstile-2' : 'cf-turnstile-1';
    let container = document.getElementById(targetId);
    if (!container) {
        container = document.createElement('div');
        container.id = targetId;
        container.style.cssText = 'visibility: hidden; position: fixed; bottom: 0; right: 0; pointer-events: none;';
        document.body.appendChild(container);
    }
    return { id: targetId, elem: container, isTab2: isTab2 };
}

function processCaptchaQueue() {
    if (!window.turnstile || !_tsLoaded) {
        if (window._3rbVerbose) console.warn('[Captcha] Turnstile SDK not ready yet.');
        return;
    }

    if (window._3rbCaptchaBusy) return;
    if (window._3rbCaptchaQueue.length === 0) return;

    const socket = window._3rbCaptchaQueue.shift();
    if (!socket) return;

    window._3rbCaptchaBusy = true;
    const label = socket._socketLabel || 'ws1';
    const sitekey = socket._3rbSitekey || '0x4AAAAAADre-KxtZJu7P6nr';
    const cInfo = getTurnstileContainer(label);

    if (window._3rbVerbose) console.log(`[Captcha] 🔐 Invisible Turnstile render starting for ${label} (${cInfo.id})...`);

    // Clean up old widget for this container if present
    if (_activeWidgets[cInfo.id] != null) {
        try {
            window.turnstile.remove(_activeWidgets[cInfo.id]);
        } catch (e) {}
        delete _activeWidgets[cInfo.id];
    }

    try {
        const widgetId = window.turnstile.render(cInfo.elem, {
            sitekey: sitekey,
            callback: function(token) {
                if (window._3rbVerbose) console.log(`[Captcha] ✅ Token solved automatically for ${label}: ${token.substring(0, 15)}...`);
                window._3rbCaptchaBusy = false;
                window._3rbToken = token;
                window._3rbTokenReady = true;
                window._3rbCaptchaSolved = true;

                if (socket) {
                    socket._3rbToken = token;
                    if (socket.readyState === WebSocket.OPEN || (socket._ws && socket._ws.readyState === WebSocket.OPEN)) {
                        try {
                            const pkt = buildCaptchaPacket(token);
                            if (typeof socket._nativeSend === 'function') {
                                socket._nativeSend(pkt);
                            } else if (socket._ws && typeof socket._ws._nativeSend === 'function') {
                                socket._ws._nativeSend(pkt);
                            } else if (typeof socket.send === 'function') {
                                socket.send(pkt);
                            }
                            socket._3rbCaptchaSent = true;
                            socket._3rbAwaitingCaptcha = false;
                            if (window._3rbVerbose) console.log(`[Captcha] ✓ Sent Opcode 123 packet to ${label}`);
                            if (socket._proxySocket && typeof socket._proxySocket._flushQueue === 'function') {
                                socket._proxySocket._flushQueue();
                            }
                        } catch (e) {
                            if (window._3rbVerbose) console.error(`[Captcha] Send error for ${label}:`, e);
                        }
                    }
                }

                // Process next queued socket if any
                if (window._3rbCaptchaQueue.length > 0) {
                    setTimeout(processCaptchaQueue, 300);
                }
            },
            'expired-callback': function() {
                if (window._3rbVerbose) console.warn(`[Captcha] Token expired for ${label}`);
                window._3rbCaptchaBusy = false;
                if (window._3rbCaptchaQueue.length > 0) setTimeout(processCaptchaQueue, 500);
            },
            'error-callback': function(err) {
                if (window._3rbVerbose) console.error(`[Captcha] Turnstile error for ${label}:`, err);
                window._3rbCaptchaBusy = false;
                if (window._3rbCaptchaQueue.length > 0) setTimeout(processCaptchaQueue, 1000);
            }
        });

        _activeWidgets[cInfo.id] = widgetId;

    } catch(e) {
        if (window._3rbVerbose) console.error(`[Captcha] Render error for ${label}:`, e);
        window._3rbCaptchaBusy = false;
        if (window._3rbCaptchaQueue.length > 0) setTimeout(processCaptchaQueue, 1000);
    }
}

// ═══════════════════════════════════════════════════════════════
// LOAD TURNSTILE API
// ═══════════════════════════════════════════════════════════════
if (window.turnstile) {
    _tsLoaded = true;
    if (window._3rbCaptchaQueue.length > 0) setTimeout(processCaptchaQueue, 100);
} else {
    window._3rbOnTurnstileLoad = function() {
        _tsLoaded = true;
        if (window._3rbVerbose) console.log('[Captcha] ✓ Turnstile API loaded.');
        if (window._3rbCaptchaQueue.length > 0) setTimeout(processCaptchaQueue, 100);
    };

    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=_3rbOnTurnstileLoad';
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);
}

// ═══════════════════════════════════════════════════════════════
// PUBLIC API - Called by hslo-mod.js when socket opens
// ═══════════════════════════════════════════════════════════════
window._3rbRequestCaptchaForSocket = function(socket, sitekey) {
    if (sitekey) socket._3rbSitekey = sitekey;
    if (!window._3rbCaptchaQueue.includes(socket)) {
        window._3rbCaptchaQueue.push(socket);
    }
    if (_tsLoaded && !window._3rbCaptchaBusy) {
        setTimeout(processCaptchaQueue, 100);
    }
};

window._3rbShowCaptcha = function() {
    if (window._3rbVerbose) console.log('[Captcha] Manual trigger called');
    if (window._3rbCaptchaQueue.length === 0) {
        window._3rbCaptchaQueue.push({ _socketLabel: 'ws1' });
    }
    processCaptchaQueue();
};
