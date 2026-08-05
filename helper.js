// helper.js - Cloudflare Turnstile Token Provider for 3rb.io (FIXED VERSION)
window._3rbCaptchaQueue = [];
window._3rbCaptchaBusy  = false;
window._3rbTokenReady = false;
window._3rbToken = null;

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

function onToken(token) {
    if (window._3rbVerbose) console.log('[Captcha] ✓ Token received:', token.substring(0, 20) + '...');
    window._3rbCaptchaBusy = false;
    clearTimeout(window._3rbCaptchaTimeout);

    // Make token globally available
    window._3rbToken = token;
    window._3rbTokenReady = true;

    // Hide captcha overlay
    const overlay = document.getElementById('captcha-overlay');
    if (overlay) {
        overlay.style.display = 'none';
    }

    const socket = window._3rbCaptchaQueue.shift();
    if (socket) {
        socket._3rbToken = token;
        const label = socket._socketLabel || 'Socket';
        if (window._3rbVerbose) console.log(`[Captcha] Token assigned to ${label}`);

        // If server already requested captcha, send immediately
        if (socket._3rbAwaitingCaptcha && socket.readyState === WebSocket.OPEN && !socket._3rbCaptchaSent) {
            try {
                // Send captcha token (handshake already sent by hslo-mod.js on open)
                const _pkt = buildCaptchaPacket(token);
                socket._nativeSend(_pkt);
                // Cache the captcha packet so a fast respawn-reconnect can REPLAY it (m.js method)
                // instead of solving a fresh captcha. Keyed per slot + on the socket.
                socket._3rbCaptchaPkt = _pkt;
                window[(socket._socketLabel === 'ws2') ? '_3rbCaptchaPkt2' : '_3rbCaptchaPkt1'] = _pkt;
                if (window._3rbTrace) window._3rbTrace("OUT", _pkt); // capture token in spawn trace
                socket._3rbCaptchaSent = true;
                socket._3rbAwaitingCaptcha = false;
                window._3rbTokenReady = false; // consumed
                if (window._3rbVerbose) console.log(`[Captcha] ✓ Token sent to server for ${label}`);
                if (socket._proxySocket && typeof socket._proxySocket._flushQueue === 'function') {
                    socket._proxySocket._flushQueue();
                }
            } catch(e) {
                if (window._3rbVerbose) console.error('[Captcha] Send error:', e);
            }
        } else {
            if (window._3rbVerbose) console.log(`[Captcha] Token pre-solved for ${label}, will be sent when requested`);
        }

        // Process next socket if any
        if (window._3rbCaptchaQueue.length > 0) {
            setTimeout(triggerWidget, 500);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// CAPTCHA OVERLAY - CENTERED, VISIBLE, WITH INSTRUCTIONS
// ═══════════════════════════════════════════════════════════════
function createCaptchaOverlay() {
    // Remove existing overlay if any
    const existing = document.getElementById('captcha-overlay');
    if (existing) existing.remove();

    const overlay = document.createElement('div');
    overlay.id = 'captcha-overlay';
    overlay.style.cssText = `
        position: fixed;
        top: 20px;
        left: 20px;
        z-index: 2147483647;
        display: flex;
        flex-direction: column;
        font-family: 'Titillium Web', sans-serif;
        color: #fff;
    `;

    const container = document.createElement('div');
    container.style.cssText = `
        background: transparent;
    `;

    const captchaWrapper = document.createElement('div');
    captchaWrapper.id = '3rb-turnstile';
    captchaWrapper.style.cssText = `
        display: flex;
        justify-content: center;
        min-height: 65px;
        opacity: 0.8;
    `;

    const loadingMsg = document.createElement('div');
    loadingMsg.id = 'captcha-loading';
    loadingMsg.textContent = 'Captcha...';
    loadingMsg.style.cssText = `
        font-size: 11px;
        color: rgba(255, 255, 255, 0.7);
        text-shadow: 1px 1px 2px black;
    `;

    container.appendChild(loadingMsg);
    container.appendChild(captchaWrapper);
    overlay.appendChild(container);
    document.body.appendChild(overlay);

    return captchaWrapper;
}

// ═══════════════════════════════════════════════════════════════
// TRIGGER WIDGET - SHOWS OVERLAY AND RENDERS TURNSTILE
// ═══════════════════════════════════════════════════════════════
let _tDiv = null;
let _tsLoaded = false;

function triggerWidget() {
    if (window._3rbVerbose) console.log('[Captcha] triggerWidget called, queue length:', window._3rbCaptchaQueue.length);
    
    if (!window.turnstile || !_tsLoaded) {
        if (window._3rbVerbose) console.warn('[Captcha] Turnstile not loaded yet');
        return;
    }
    
    if (window._3rbCaptchaBusy) {
        if (window._3rbVerbose) console.log('[Captcha] Already busy, skipping');
        return;
    }

    if (window._3rbCaptchaQueue.length === 0) {
        if (window._3rbVerbose) console.log('[Captcha] Queue empty, nothing to do');
        return;
    }

    window._3rbCaptchaBusy = true;

    // Create overlay and get captcha container
    _tDiv = createCaptchaOverlay();
    
    // Hide loading message
    setTimeout(() => {
        const loading = document.getElementById('captcha-loading');
        if (loading) loading.style.display = 'none';
    }, 500);

    // Get sitekey from socket or use default
    const socket = window._3rbCaptchaQueue[0];
    const sitekey = (socket && socket._3rbSitekey) ? socket._3rbSitekey : '0x4AAAAAADre-KxtZJu7P6nr';
    
    if (window._3rbVerbose) console.log('[Captcha] Rendering Turnstile with sitekey:', sitekey);

    // Remove old widget if exists
    try {
        if (_tDiv._wid != null) {
            window.turnstile.remove(_tDiv._wid);
            _tDiv._wid = null;
        }
    } catch(e) {
        if (window._3rbVerbose) console.warn('[Captcha] Error removing old widget:', e);
    }

    // Render new widget
    try {
        _tDiv._wid = window.turnstile.render(_tDiv, {
            sitekey: sitekey,
            theme: 'dark',
            size: 'normal',
            callback: onToken,
            'expired-callback': function() {
                if (window._3rbVerbose) console.warn('[Captcha] Token expired');
                window._3rbCaptchaBusy = false;
                window._3rbTokenReady = false;
                if (window._3rbCaptchaQueue.length > 0) {
                    setTimeout(triggerWidget, 1000);
                }
            },
            'error-callback': function(code) {
                if (window._3rbVerbose) console.error('[Captcha] Turnstile error:', code);
                window._3rbCaptchaBusy = false;
                
                // Show error message
                const loading = document.getElementById('captcha-loading');
                if (loading) {
                    loading.textContent = '⚠ Verification failed. Retrying in 5 seconds...';
                    loading.style.color = '#ff3d55';
                    loading.style.display = 'block';
                }
                
                if (window._3rbCaptchaQueue.length > 0) {
                    setTimeout(triggerWidget, 5000);
                }
            },
            'timeout-callback': function() {
                if (window._3rbVerbose) console.warn('[Captcha] Timeout');
                window._3rbCaptchaBusy = false;
                if (window._3rbCaptchaQueue.length > 0) {
                    setTimeout(triggerWidget, 2000);
                }
            }
        });

        if (window._3rbVerbose) console.log('[Captcha] Widget rendered with ID:', _tDiv._wid);

        // Safety timeout: if no token in 45 seconds, retry
        clearTimeout(window._3rbCaptchaTimeout);
        window._3rbCaptchaTimeout = setTimeout(function() {
            if (window._3rbCaptchaBusy) {
                if (window._3rbVerbose) console.warn('[Captcha] Safety timeout (45s) — retrying...');
                window._3rbCaptchaBusy = false;
                if (window._3rbCaptchaQueue.length > 0) {
                    triggerWidget();
                }
            }
        }, 45000);

    } catch(e) {
        if (window._3rbVerbose) console.error('[Captcha] Render error:', e);
        window._3rbCaptchaBusy = false;
        
        // Show error
        const loading = document.getElementById('captcha-loading');
        if (loading) {
            loading.textContent = '⚠ Failed to load captcha. Please refresh the page.';
            loading.style.color = '#ff3d55';
            loading.style.display = 'block';
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// LOAD TURNSTILE API
// ═══════════════════════════════════════════════════════════════
if (window.turnstile) {
    _tsLoaded = true;
    if (window._3rbVerbose) console.log('[Captcha] ✓ Turnstile already loaded');
    if (window._3rbCaptchaQueue.length > 0) {
        setTimeout(triggerWidget, 200);
    }
} else {
    if (window._3rbVerbose) console.log('[Captcha] Loading Turnstile API...');
    const _ts = document.createElement('script');
    _ts.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit&onload=_3rbOnTurnstileLoad';
    _ts.async = true;
    _ts.defer = true;
    
    // Define callback before script loads
    window._3rbOnTurnstileLoad = function() {
        _tsLoaded = true;
        if (window._3rbVerbose) console.log('[Captcha] ✓ Turnstile API loaded successfully');
        if (window._3rbCaptchaQueue.length > 0) {
            setTimeout(triggerWidget, 300);
        }
    };
    
    _ts.onerror = function(e) {
        if (window._3rbVerbose) console.error('[Captcha] ✗ Failed to load Turnstile API!', e);
        
        // Show error overlay
        const overlay = document.createElement('div');
        overlay.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: rgba(255, 61, 85, 0.9);
            color: white;
            padding: 20px 40px;
            border-radius: 8px;
            font-family: 'Titillium Web', sans-serif;
            font-size: 16px;
            z-index: 2147483647;
            box-shadow: 0 0 30px rgba(255, 61, 85, 0.5);
        `;
        overlay.textContent = '⚠ Failed to load captcha system. Please refresh the page.';
        document.body.appendChild(overlay);
    };
    
    document.head.appendChild(_ts);
}

// ═══════════════════════════════════════════════════════════════
// PUBLIC API - Called by ws-proxy.js when server requests captcha
// ═══════════════════════════════════════════════════════════════
window._3rbRequestCaptchaForSocket = function(socket, sitekey) {
    if (window._3rbVerbose) console.log('[Captcha] Request received for socket:', socket._socketLabel || 'Unknown');
    
    if (sitekey) {
        socket._3rbSitekey = sitekey;
        if (window._3rbVerbose) console.log('[Captcha] Using custom sitekey:', sitekey);
    }
    
    // Add to queue if not already there
    if (!window._3rbCaptchaQueue.includes(socket)) {
        window._3rbCaptchaQueue.push(socket);
        if (window._3rbVerbose) console.log('[Captcha] Added to queue, new length:', window._3rbCaptchaQueue.length);
    }
    
    // Trigger widget if ready and not busy
    if (_tsLoaded && !window._3rbCaptchaBusy) {
        setTimeout(triggerWidget, 100);
    } else {
        if (window._3rbVerbose) console.log('[Captcha] Waiting... Loaded:', _tsLoaded, 'Busy:', window._3rbCaptchaBusy);
    }
};

// ═══════════════════════════════════════════════════════════════
// MANUAL TRIGGER - For debugging
// ═══════════════════════════════════════════════════════════════
window._3rbShowCaptcha = function() {
    if (window._3rbVerbose) console.log('[Captcha] Manual trigger');
    if (!_tsLoaded) {
        if (window._3rbVerbose) console.error('[Captcha] Turnstile not loaded yet!');
        return;
    }
    
    // Create dummy socket if queue is empty
    if (window._3rbCaptchaQueue.length === 0) {
        const dummySocket = { _socketLabel: 'Manual Test' };
        window._3rbCaptchaQueue.push(dummySocket);
    }
    
    triggerWidget();
};

if (window._3rbVerbose) console.log('[Captcha] Helper initialized. Use _3rbShowCaptcha() to test manually.');
