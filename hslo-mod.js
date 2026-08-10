// hslo-mod.js - WebSocket Proxy for HSLO v5 on 3rb.io

const OriginalWebSocket = window.WebSocket;

// Disable browser default right-click context menu on game canvas only
window.addEventListener('contextmenu', e => {
    if (e.target && e.target.tagName === 'CANVAS') e.preventDefault();
}, { capture: true });

window._3rbVerbose = false;
const log = (...args) => { if (window._3rbVerbose) window._3rbVerbose && console.log('[hslo-mod]', ...args); };

// ── HSLO message-cipher (mirrored from bundle.js class `j` / window.classj) ──
// HSLO encrypts every packet it sends with a per-tab `clientKey` and refuses to
// send ANYTHING while that key is null (sendPacket: `if (!j.clientKey) return`).
// The real 3rb server never performs HSLO's op-241 key handshake, so the key stays
// null and Play does nothing. We seed the key ourselves and mirror the exact same
// rotation here so we can decrypt (un-shift) each outgoing packet before translating.
const HSLO_VERSION_INT = 30601; // matches "Current Client Version: 30601"
const HSLO_SEED_KEY = 0x5151ABCD; // any fixed non-zero uint32; both sides start here

function hsloShiftKey(e) {
    e = 0 | Math.imul(e, 1540483477);
    e = 114296087 ^ (0 | Math.imul(e >>> 24 ^ e, 1540483477));
    return (e = 0 | Math.imul(e >>> 13 ^ e, 1540483477)) >>> 15 ^ e;
}

// XOR each byte with the rolling key (self-inverse: same call shifts and un-shifts).
function hsloShiftMessage(u8, key) {
    for (let o = 0; o < u8.length; o++) {
        u8[o] ^= 255 & (key >>> (o % 4 * 8));
    }
    return u8;
}

// Helper to read zero-terminated UTF-8 string
function readZStr(view, offset) {
    let start = offset;
    while (offset < view.byteLength) {
        if (view.getUint8(offset) === 0) break;
        offset++;
    }
    const bytes = new Uint8Array(view.buffer, view.byteOffset + start, offset - start);
    const decoder = new TextDecoder("utf-8");
    return {
        str: decoder.decode(bytes),
        nextOffset: offset + 1
    };
}

// Translate 3rb.io V5 Opcode 16 format to standard HSLO V5 format
function translateOpcode16(data, proxySelf) {
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    let offset = 0;
    
    const out = [];
    function u8(val) { out.push(val); }
    function u16(val) { out.push(val & 255, (val >> 8) & 255); }
    function u32(val) { out.push(val & 255, (val >> 8) & 255, (val >> 16) & 255, (val >> 24) & 255); }
    
    u8(16);
    offset++;
    
    if (offset + 2 > view.byteLength) return new Uint8Array(out);
    const eatCount = view.getUint16(offset, true); offset += 2;
    u16(eatCount);
    for (let i = 0; i < eatCount; i++) {
        if (offset + 8 > view.byteLength) break;
        u32(view.getUint32(offset, true)); offset += 4;
        u32(view.getUint32(offset, true)); offset += 4;
    }
    
    let listClosed = false;
    while (offset + 4 <= view.byteLength) {
        const id = view.getUint32(offset, true); offset += 4;
        if (id === 0) { u32(0); listClosed = true; break; }
        if (offset + 11 > view.byteLength) { u32(0); listClosed = true; break; }

        const x = view.getInt32(offset, true); offset += 4;
        const y = view.getInt32(offset, true); offset += 4;
        const sz = view.getUint16(offset, true); offset += 2;
        const fl = view.getUint8(offset); offset += 1;

        let hasAccount = false;
        let accountId = 0;
        let ownerId = -1;

        // fl & 16: alignment padding (u32 + u8 = 5 bytes). NOT the owner ID.
        if (fl & 16) {
            if (offset + 5 <= view.byteLength) {
                offset += 5; // skip padding
            }
        }
        // fl & 64: the actual owner/player ID in 3rb V5.
        if (fl & 64) {
            if (offset + 4 <= view.byteLength) {
                ownerId = view.getInt32(offset, true); offset += 4;
                accountId = ownerId >>> 0; // unsigned for HSLO account field
                hasAccount = true;
            }
        }

        let r=0, g=0, b=0;
        let hasColor = false;
        if (fl & 2) {
            hasColor = true;
            if (offset + 3 <= view.byteLength) {
                r = view.getUint8(offset++);
                g = view.getUint8(offset++);
                b = view.getUint8(offset++);
            }
        }

        let skin = [];
        let skinStr = '';
        if (fl & 4) {
            while (offset < view.byteLength) {
                const bVal = view.getUint8(offset++);
                skin.push(bVal);
                if (bVal === 0) break;
            }
            // Decode the raw skin string from 3rb.io
            skinStr = new TextDecoder().decode(new Uint8Array(skin.slice(0, -1)));
            // Resolve to a full URL (mirrors Ryuten's imgurHash):
            //  - Full URL (has "://") or data URI → keep as-is
            //  - imgur domain without scheme → prepend https://
            //  - Absolute path (starts "/") → prepend 3rb.io origin
            //  - Asset path (starts "res/") → prepend 3rb.io origin
            //  - Bare preset code (e.g. "free/3") → https://3rb.io/res/skins/{code}.png
            if (skinStr) {
                // Filter out 3rb.io meta/invalid skin values
                const invalidSkins = ['removed', 'none', 'null', 'undefined', ''];
                if (invalidSkins.includes(skinStr.toLowerCase())) {
                    skin = []; // discard the skin entirely
                    skinStr = '';
                } else {
                    let resolved;
                    const sTrim = skinStr.trim();
                    if (sTrim.includes('://') || sTrim.startsWith('data:')) resolved = sTrim;
                    else if (sTrim.includes('imgur.com')) resolved = 'https://' + sTrim.replace(/^\/+/, '');
                    else if (sTrim.startsWith('/')) resolved = 'https://3rb.io' + sTrim;
                    else if (sTrim.startsWith('res/')) resolved = 'https://3rb.io/' + sTrim;
                    else if (sTrim.startsWith('free/')) resolved = 'https://3rb.io/res/skins/free/' + sTrim.replace(/^free\//, '').replace(/\.png$/, '') + '.png';
                    else if (/^\d+$/.test(sTrim)) resolved = 'https://3rb.io/res/skins/free/' + sTrim + '.png';
                    else if (/^[a-zA-Z0-9]{5,10}$/.test(sTrim) && /[a-zA-Z]/.test(sTrim)) resolved = 'https://i.imgur.com/' + sTrim + '.png';
                    else resolved = 'https://3rb.io/res/skins/' + sTrim + '.png';
                    // Re-encode the resolved URL back to bytes for HSLO's parser
                    const resolvedBytes = new TextEncoder().encode(resolved);
                    skin = Array.from(resolvedBytes);
                    skin.push(0); // null terminator
                }
            }
        }

        let name = [];
        let nameStr = '';
        if (fl & 8) {
            while (offset < view.byteLength) {
                const bVal = view.getUint8(offset++);
                name.push(bVal);
                if (bVal === 0) break;
            }
            if (name.length > 1) {
                nameStr = new TextDecoder().decode(new Uint8Array(name.slice(0, -1)));
            }
        }

        // 3rb sets flag 128 for an EXTRA null-terminated string. The old parser
        // ignored it, so every packet containing one drifted out of alignment and
        // produced garbage cells. Consume and discard it (HSLO has no use for it).
        if (fl & 128) {
            while (offset < view.byteLength && view.getUint8(offset++) !== 0);
        }

        // Misalignment safety (ryuten parity): absurd values mean the parser drifted —
        // close the cell list cleanly instead of emitting garbage.
        if (sz > 10000 || x < -60000 || x > 60000 || y < -60000 || y > 60000) {
            u32(0); listClosed = true; break;
        }

        // Track owner to ensure all pieces of a player have the same color
        if (proxySelf) {
            if (!proxySelf.ws._3rbNodeToOwner) proxySelf.ws._3rbNodeToOwner = new Map();
            if (ownerId !== -1) proxySelf.ws._3rbNodeToOwner.set(id, ownerId);
            else if (proxySelf.ws._3rbNodeToOwner.has(id)) ownerId = proxySelf.ws._3rbNodeToOwner.get(id);
        }

        // Determine if cell is Food and needs sweeping
        const isVirus = (fl & 1) !== 0;
        const ownerIdUnsigned = ownerId !== -1 ? (ownerId >>> 0) : -1;
        const isTab1Mine = ownerId !== -1 && window._3rbPlayerId && (ownerIdUnsigned === (window._3rbPlayerId >>> 0));
        const isTab2Mine = ownerId !== -1 && (
            (window._3rbPlayerId2Real && ownerIdUnsigned === (window._3rbPlayerId2Real >>> 0)) ||
            (window._3rbPlayerId2 && ownerIdUnsigned === (window._3rbPlayerId2 >>> 0))
        );
        const oidIsMine = isTab1Mine || isTab2Mine;
        if (isTab1Mine) {
            window._3rbMyPos = { x: x, y: y };
        } else if (isTab2Mine) {
            window._crizoTab2Pos = { x: x, y: y };
        }
        // Better food classification: nameless, ownerless, non-virus, and not ejected mass (!(fl & 32))
        const isFood = !isVirus && !(fl & 32) && name.length === 0 && ownerId === -1;

        // Track non-food cells for the ghost-cell GC sweep — but NEVER our OWN cells. During lag
        // the world stops updating; if the GC swept our own cells HSLO would think we died and pop
        // the menu-overlay mid-game. Our real death always arrives as an explicit server remove
        // (handled below), so own cells don't need the GC safety net.
        if (!isFood && !oidIsMine && proxySelf) {
            if (!proxySelf.ws._3rbLastSeen) proxySelf.ws._3rbLastSeen = new Map();
            proxySelf.ws._3rbLastSeen.set(id, Date.now());
        }

        // Cache and synchronize colors to prevent flashing
        if (proxySelf) {
            if (!proxySelf.ws._3rbCellColors) proxySelf.ws._3rbCellColors = new Map();
            if (!proxySelf.ws._3rbOwnerColors) proxySelf.ws._3rbOwnerColors = new Map();

            // 1. If ownerId is known, try resolving from owner cache
            if (ownerId !== -1) {
                if (hasColor) {
                    proxySelf.ws._3rbOwnerColors.set(ownerId, { r, g, b });
                } else if (proxySelf.ws._3rbOwnerColors.has(ownerId)) {
                    const cached = proxySelf.ws._3rbOwnerColors.get(ownerId);
                    r = cached.r;
                    g = cached.g;
                    b = cached.b;
                    hasColor = true;
                }
            }

            // 2. Try resolving from cell cache
            if (hasColor) {
                proxySelf.ws._3rbCellColors.set(id, { r, g, b });
            } else if (proxySelf.ws._3rbCellColors.has(id)) {
                const cached = proxySelf.ws._3rbCellColors.get(id);
                r = cached.r;
                g = cached.g;
                b = cached.b;
                hasColor = true;
            }
        }

        // 3. Fallback to deterministic colors if still no color
        if (!hasColor) {
            const hashId = ownerId !== -1 ? ownerId : id;
            const h = (hashId * 2654435761) >>> 0;
            r = (h & 0x7F) + 0x80; // 128-255 (bright)
            g = ((h >>> 8) & 0x7F) + 0x80;
            b = ((h >>> 16) & 0x7F) + 0x80;
            if (proxySelf) {
                proxySelf.ws._3rbCellColors.set(id, { r, g, b });
                if (ownerId !== -1) {
                    proxySelf.ws._3rbOwnerColors.set(ownerId, { r, g, b });
                }
            }
        }

        u32(id);
        u32(x); u32(y); 
        if (isVirus) {
            u16(Math.floor(sz * 1.8));
        } else {
            u16(sz);
        }

        let newFl = fl & ~(16 | 64 | 128);
        if (hasAccount) newFl |= 128;
        if (isFood) newFl |= 128;
        newFl |= 2; // Always force color flag to true for HSLO

        // Check for shared party skins
        let partySkinUrl = null;
        if (window._3rbPartySkins && !oidIsMine) {
            if (ownerId !== -1 && window._3rbPartySkins[ownerId]) {
                partySkinUrl = window._3rbPartySkins[ownerId];
            } else if (nameStr) {
                let cleanNm = nameStr.replace(/^(?:❋|\[\])\s*/, '').trim();
                partySkinUrl = window._3rbPartySkins[cleanNm] || window._3rbPartySkins[nameStr.trim()];
            }
        }

        if (partySkinUrl) {
            newFl |= 4; // Force skin flag
            let resolvedPartySkin = partySkinUrl;
            if (!resolvedPartySkin.includes('://') && !resolvedPartySkin.startsWith('data:')) {
                if (resolvedPartySkin.includes('imgur.com')) {
                    resolvedPartySkin = 'https://' + resolvedPartySkin.replace(/^\/+/, '');
                } else if (resolvedPartySkin.startsWith('/')) {
                    resolvedPartySkin = 'https://3rb.io' + resolvedPartySkin;
                } else if (resolvedPartySkin.startsWith('res/')) {
                    resolvedPartySkin = 'https://3rb.io/' + resolvedPartySkin;
                } else if (resolvedPartySkin.length < 15 && !resolvedPartySkin.includes('/')) {
                    // It's probably a bare imgur code like HSLO defaults to
                    resolvedPartySkin = 'https://i.imgur.com/' + resolvedPartySkin + '.png';
                } else {
                    resolvedPartySkin = 'https://3rb.io/res/skins/' + resolvedPartySkin + '.png';
                }
            }

            const resolvedBytes = new TextEncoder().encode(resolvedPartySkin);
            skin = Array.from(resolvedBytes);
            skin.push(0); // null terminator
        }

        u8(newFl);
        if (newFl & 128) {
            let l = 0;
            if (hasAccount) l |= 4;
            if (isFood) l |= 1;
            u8(l);
        }

        if (newFl & 2) { u8(r); u8(g); u8(b); }
        if (newFl & 4) { for (let i=0; i<skin.length; i++) u8(skin[i]); }
        if (newFl & 8) { for (let i=0; i<name.length; i++) u8(name[i]); }
        if (hasAccount) u32(accountId);
    }
    if (!listClosed) u32(0); // always terminate the cell list for HSLO's parser

    if (offset + 2 <= view.byteLength) {
        const removeCount = view.getUint16(offset, true); offset += 2;
        u16(removeCount);
        for (let i = 0; i < removeCount; i++) {
            if (offset + 4 <= view.byteLength) {
                const remId = view.getUint32(offset, true);
                offset += 4;
                u32(remId);
                if (proxySelf) {
                    if (proxySelf.ws._3rbLastSeen) proxySelf.ws._3rbLastSeen.delete(remId);
                    if (proxySelf.ws._3rbCellColors) proxySelf.ws._3rbCellColors.delete(remId);
                }
            }
        }
    } else {
        u16(0); // truncated input — emit an empty remove list so HSLO stays aligned
    }

    return new Uint8Array(out);
}

// LZ4 block compression wrapper for raw literal payloads
function lz4CompressLiterals(data) {
    const L = data.length;
    const header = [];
    if (L < 15) {
        header.push(L << 4);
    } else {
        header.push(15 << 4);
        let remaining = L - 15;
        while (remaining >= 255) {
            header.push(255);
            remaining -= 255;
        }
        header.push(remaining);
    }
    
    const buf = new ArrayBuffer(1 + 4 + header.length + L);
    const u8 = new Uint8Array(buf);
    const dv = new DataView(buf);
    
    u8[0] = 255; // Opcode
    dv.setUint32(1, L, true); // Decompressed length
    u8.set(header, 5); // Copy header
    u8.set(data, 5 + header.length); // Copy literal data
    
    return buf;
}

// ── Custom map background image ──
(function setMapBackground() {
    const BG_URL = 'https://i.imgur.com/aKvo1jQ.png';
    let tries = 0;
    const trySet = () => {
        // Wait for HSLO settings & renderer singletons to appear
        if (window.k && window.oe && window.re) {
            window.k.bgImg = 'on';           // enable background rendering
            window.oe.customBG = BG_URL;      // set the URL in theme object
            if (typeof window.re.getBGImg === 'function') {
                window.re.getBGImg(BG_URL);   // load the image into fantasyImg
                log('bg', '✓ Map background set to ' + BG_URL);
            }
            return;
        }
        if (tries++ < 100) setTimeout(trySet, 200);
    };
    trySet();
})();

// ── Auto-hide HUDs while the menu overlay is open (and restore in-game) ──
// When #menu-overlay is visible we hide #huds; when it closes (player is in-game) we
// restore them — unless the user has intentionally hidden HUDs via the H key (k.hideHUDs).
(function autoHideHudsWithMenu() {
    const start = () => {
        const overlay = document.getElementById('menu-overlay');
        const huds = document.getElementById('huds');
        if (!overlay || !huds) { setTimeout(start, 300); return; }

        const apply = () => {
            const menuVisible = getComputedStyle(overlay).display !== 'none';
            if (menuVisible) {
                huds.style.display = 'none';
            } else {
                const userHidHuds = window.k && window.k.hideHUDs === 'on';
                huds.style.display = userHidHuds ? 'none' : '';
            }
        };

        new MutationObserver(apply).observe(overlay, { attributes: true, attributeFilter: ['style', 'class'] });
        apply(); // sync initial state (menu is open at load → HUDs hidden)
        log('hud', '✓ Auto-hide HUDs bound to menu overlay');
    };
    start();
})();

window._3rbParty = {};
window._3rbSyncHsloTeams = function() {
    if (!window.se) return;
    const activeIds = new Set();
    const now = window.le ? window.le.time : performance.now();
    
    for (const id in window._3rbParty) {
        const m = window._3rbParty[id];
        
        // Skip self
        const isSelf = 
            (window._3rbPlayerId && id == window._3rbPlayerId) ||
            (window._3rbPlayerId2Real && id == window._3rbPlayerId2Real) ||
            (window._3rbPlayerId2 && id == window._3rbPlayerId2);
        if (isSelf) continue;
        
        activeIds.add(id);
        const playerID = parseInt(id, 10);
        let player = window.se.teammates.get(playerID);
        const isNew = !player;
        if (isNew) player = window.se.getPlayer(playerID);
        player.nick = m.name || "Party Member";
        player.x = m.x;
        player.y = m.y;
        // Snap animX/Y on first appearance so the dot doesn't drift in from center
        if (isNew) { player.animX = m.x; player.animY = m.y; }
        player.mass = m.mass || 100;
        let pSkin = m.skin || "";
        if (!pSkin && window._3rbPartySkins) {
            let nClean = (m.name || "").replace(/^(?:‹|\[\])\s*/, '').trim();
            pSkin = window._3rbPartySkins[id] || window._3rbPartySkins[nClean] || window._3rbPartySkins[m.name] || "";
        }
        player.skin = pSkin;
        player.colorHex = m.colorHex || "#ffffff";
        player.isAlive = 1;
        player.lastUpdateAt = now;
        player.timeStamp = now;
    }
    
    // Remove stale teammates
    for (const id of window.se.teammates.keys()) {
        if (!activeIds.has(id.toString())) {
            window.se.teammates.delete(id);
        }
    }
    
    // Do the same for Tab 2 (ses) if active
    if (window.ses) {
        const activeIds2 = new Set();
        for (const id in window._3rbParty) {
            const m = window._3rbParty[id];
            const isSelf = 
                (window._3rbPlayerId && id == window._3rbPlayerId) ||
                (window._3rbPlayerId2Real && id == window._3rbPlayerId2Real) ||
                (window._3rbPlayerId2 && id == window._3rbPlayerId2);
            if (isSelf) continue;
            
            activeIds2.add(id);
            const playerID = parseInt(id, 10);
            let player = window.ses.teammates.get(playerID);
            if (!player) {
                player = window.ses.getPlayer(playerID);
            }
            player.nick = m.name || "Party Member";
            player.x = m.x;
            player.y = m.y;
            player.mass = m.mass || 100;
            let pSkin = m.skin || "";
            if (!pSkin && window._3rbPartySkins) {
                let nClean = (m.name || "").replace(/^(?:‹|\[\])\s*/, '').trim();
                pSkin = window._3rbPartySkins[id] || window._3rbPartySkins[nClean] || window._3rbPartySkins[m.name] || "";
            }
            player.skin = pSkin;
            player.colorHex = m.colorHex || "#ffffff";
            player.isAlive = 1;
            player.lastUpdateAt = now;
            player.timeStamp = now;
        }
        for (const id of window.ses.teammates.keys()) {
            if (!activeIds2.has(id.toString())) {
                window.ses.teammates.delete(id);
            }
        }
    }
};

// ── Mock WebSocket for non-game connections (bot server, ogario, etc.) ──
// These sockets get opened, fire onopen immediately, and silently ignore all messages.
class MockWebSocket {
    constructor(url) {
        this.url = url;
        this.readyState = 0; // CONNECTING
        this.binaryType = 'arraybuffer';
        this.protocol = '';
        this.extensions = '';
        this._events = {};
        this._label = 'mock';

        // Simulate async open
        setTimeout(() => {
            this.readyState = 1; // OPEN
            log(this._label, 'mock opened (fake)');
            if (this.onopen) this.onopen(new Event('open'));
            this._dispatch('open', new Event('open'));
        }, 50);
    }
    send(data) { /* silently discard */ }
    close() {
        if (this.readyState === 3) return;
        this.readyState = 3; // CLOSED
        const ev = new CloseEvent('close', { code: 1000, reason: 'mock', wasClean: true });
        if (this.onclose) this.onclose(ev);
        this._dispatch('close', ev);
    }
    addEventListener(type, fn) {
        if (!this._events[type]) this._events[type] = [];
        this._events[type].push(fn);
    }
    removeEventListener(type, fn) {
        if (!this._events[type]) return;
        this._events[type] = this._events[type].filter(l => l !== fn);
    }
    _dispatch(type, ev) {
        if (this._events[type]) this._events[type].forEach(fn => fn(ev));
    }
}

// ── Real ProxyWebSocket for 3rb.io game connections ──
class ProxyWebSocket {
    constructor(url, protocols) {
        log('Intercepted connection to:', url);
        
        // Fix double protocol: wss://wss://... -> wss://...
        let targetUrl = url.replace(/^wss:\/\/wss:\/\//i, 'wss://').replace(/^ws:\/\/wss:\/\//i, 'wss://');
        
        // Bot server (localhost) and Ogario — return mock, don't waste captcha slots
        if (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') || targetUrl.includes('ogario')) {
            log('Mocking non-game connection:', targetUrl);
            const mock = new MockWebSocket(targetUrl);
            mock._label = window._3rbSocketCounter ? `mock${++window._3rbSocketCounter}` : (() => { window._3rbSocketCounter = 1; return 'mock1'; })();
            // Copy event handler properties so bundle.js can set them
            ['onopen', 'onmessage', 'onclose', 'onerror'].forEach(prop => {
                Object.defineProperty(mock, prop, {
                    get: function() { return this['_' + prop]; },
                    set: function(val) { this['_' + prop] = val; }
                });
            });
            return mock;
        }
        
        // If not already pointing at 3rb.io, redirect
        if (!targetUrl.includes('3rb.io')) {
            const mySelect = document.getElementById('_3rb_server_select');
            if (mySelect && mySelect.value) {
                targetUrl = mySelect.value;
            } else {
                targetUrl = 'wss://alpha2.3rb.io:1777/V5';
            }
            log('Redirecting to', targetUrl);
        }

        const is3rb = targetUrl.includes('3rb.io');
        this._socketLabel = window._3rbSocketCounter ? `ws${++window._3rbSocketCounter}` : (() => { window._3rbSocketCounter = 1; return 'ws1'; })();
        log('Created socket', this._socketLabel, 'for', targetUrl);

        // 3rb.io REQUIRES subprotocol "ghmarab" — without it the server rejects as "Spam"
        if (is3rb) {
            this.ws = new OriginalWebSocket(targetUrl, 'ghmarab');
        } else {
            this.ws = protocols ? new OriginalWebSocket(targetUrl, protocols) : new OriginalWebSocket(targetUrl);
        }
        this.ws.binaryType = 'arraybuffer';
        
        this._is3rb = is3rb;
        this.ws._socketLabel = this._socketLabel;
        this.ws._proxySocket = this;
        this.ws._nativeSend = this.ws.send.bind(this.ws);
        this.ws._3rbCaptchaSent = false;
        this.ws._3rbPacketQueue = [];
        this.ws._3rbHandshakeSent = false;

        // Slot assignment: first live 3rb socket = Tab 1, second = Tab 2. A reconnect
        // reuses a slot whose previous socket is closing/closed. (The old check against
        // window.Tab1WS matched nothing — every socket landed on slot 2.)
        if (is3rb) {
            if (!window._3rbSlot1Sock || window._3rbSlot1Sock.readyState > 1) {
                window._3rbSlot1Sock = this.ws;
                window._3rbProxySlot1 = this;
                this._slot = 1;
            } else {
                window._3rbSlot2Sock = this.ws;
                window._3rbProxySlot2 = this;
                this._slot = 2;
            }
            log(this._socketLabel, '→ assigned slot', this._slot);
        }
        
        this.events = {};

        const self = this;
        this.ws.onopen = function(e) {
            log(self._socketLabel, 'opened');
            if (self._is3rb) {
                // 0. Seed HSLO's per-tab clientKey so its sendPacket() stops bailing out.
                // We mirror the same key here to decrypt the packets HSLO will send. We do
                // NOT touch protocolKey (leaving it null means HSLO does NOT decrypt incoming
                // frames, so our translated packets reach its parser untouched).
                self.ws._3rbMirrorKey = HSLO_SEED_KEY >>> 0;
                const keyProp = self._slot === 2 ? 'clientKey2' : 'clientKey';
                let seedTries = 0;
                const seedKey = () => {
                    if (window.classj) {
                        window.classj[keyProp] = HSLO_SEED_KEY >>> 0;
                        // protocolKey must stay falsy so HSLO does NOT decrypt incoming frames.
                        log(self._socketLabel, `✓ Seeded HSLO ${keyProp} (Play unlocked)`);
                        return;
                    }
                    if (seedTries++ < 50) setTimeout(seedKey, 200); // wait for bundle.js to expose classj
                    else log(self._socketLabel, '⚠ window.classj never appeared — cannot unlock sending');
                };
                seedKey();

                // 1. Send version handshake immediately (like original 3rb client)
                self.ws._nativeSend(new Uint8Array([255, 0, 0]).buffer);
                self.ws._3rbHandshakeSent = true;
                self.ws._3rbCaptchaSent = true;
                log(self._socketLabel, '✓ Handshake [255,0,0] sent');

                // 2. Start ping loop [0x64] every 1s — but ONLY after the captcha token is
                // sent. 3rb.io treats keepalive pings sent before authentication as abuse and
                // closes the socket with code 1009 "Spam" (this bit us: pings during the
                // seconds the user spends solving the captcha tripped the limiter).
                self.ws._3rbPingInterval = setInterval(function() {
                    if (self.ws.readyState !== WebSocket.OPEN) {
                        clearInterval(self.ws._3rbPingInterval);
                        return;
                    }
                    if (self.ws._3rbCaptchaSent) {
                        self.ws._nativeSend(new Uint8Array([0x64]).buffer);
                    }
                }, 1000);

                // 3. Request captcha
                self.ws._3rbAwaitingCaptcha = true;
                if (window._3rbRequestCaptchaForSocket) {
                    window._3rbRequestCaptchaForSocket(self.ws);
                }

                // 4. Garbage Collector for stuck ghost cells
                self.ws._3rbGCLoop = setInterval(() => {
                    if (self.ws.readyState !== WebSocket.OPEN) {
                        clearInterval(self.ws._3rbGCLoop);
                        return;
                    }
                    if (!self.ws._3rbLastSeen) return;
                    
                    const cutoff = Date.now() - 1000;
                    const stale = [];
                    for (const [id, last] of self.ws._3rbLastSeen) {
                        if (last < cutoff) {
                            stale.push(id);
                            self.ws._3rbLastSeen.delete(id);
                        }
                    }
                    if (stale.length > 0) {
                        const buf = new Uint8Array(9 + (stale.length * 4));
                        const v = new DataView(buf.buffer);
                        buf[0] = 16;
                        v.setUint16(1, 0, true);
                        v.setUint32(3, 0, true);
                        v.setUint16(7, stale.length, true);
                        let off = 9;
                        for (let i = 0; i < stale.length; i++) {
                            v.setUint32(off, stale[i], true);
                            off += 4;
                        }
                        const compressed = lz4CompressLiterals(buf);
                        if (self.onmessage) self.onmessage({ data: compressed });
                        self.dispatchEvent(new MessageEvent('message', { data: compressed }));
                        // log(self._socketLabel, `[GC] Swept ${stale.length} stuck ghost cells`);
                    }
                }, 1000);
            }
            if (self.onopen) self.onopen(e);
            self.dispatchEvent(new Event('open'));
        };

        this.ws.onmessage = function(e) {
            if (self._is3rb && e.data instanceof ArrayBuffer) {
                const view = new DataView(e.data);
                
                // 1. Intercept SIG (opcode mapping)
                if (e.data.byteLength === 266 && view.getUint8(0) === 83 && view.getUint8(1) === 73 && view.getUint8(2) === 71) {
                    const qe = new Uint8Array(e.data, 10, 256);
                    const Re = new Uint8Array(256);
                    for (let i = 0; i < 256; i++) Re[qe[i]] = i;
                    self.ws._3rbQe = qe;
                    self.ws._3rbRe = Re;
                    log(self._socketLabel, '✓ Captured opcode mapping (SIG)');
                    return; // Drop the SIG packet from HSLO
                }

                // 2. Unshuffle the incoming opcode
                let rawOp = view.getUint8(0);
                let op = self.ws._3rbRe ? self.ws._3rbRe[rawOp] : rawOp;
                
                // 3. (Deprecated) Handle captcha verification
                if (op === 254) {
                    return; // drop the verification packet if it ever arrives
                }

                // 3b. Drop everything the server sends BEFORE the captcha is validated.
                // That pre-auth chatter (e.g. the 1-byte "send captcha" request, op 18) isn't
                // real game data; feeding it to HSLO's parser throws "Offset is outside the
                // bounds of the DataView" / "URI malformed" on every frame. SIG (line above)
                // and the captcha-OK frame (op 254, above) are handled before this guard, so
                // they still pass. Once validated, frames flow through normally — with or
                // without a SIG opcode map (this server may not send one).
                // Exception: op 65 (Border + pid) arrives at CONNECT time, before the
                // captcha — it carries the map bounds and our player id, and dropping it
                // leaves HSLO with no world to render. Let it through; hold the rest.
                if (!self.ws._3rbCaptchaSent && op !== 65) {
                    if (!self.ws._3rbWarnedPreAuth) {
                        self.ws._3rbWarnedPreAuth = true;
                        log(self._socketLabel, `Holding pre-captcha frames (first frame ${e.data.byteLength}B, raw op ${rawOp})`);
                    }
                    return;
                }

                // 4a. One-time-per-opcode census of post-captcha traffic. Cells aren't
                // drawing and the leaderboard is frozen, so we need to see which RAW 3rb
                // opcodes (and their lengths) actually arrive before trusting any handler.
                // Each distinct opcode is logged once; full tallies live in window._3rbOpStats.
                window._3rbOpStats = window._3rbOpStats || {};
                if (!window._3rbOpStats[rawOp]) {
                    const preview = new Uint8Array(e.data, 0, Math.min(e.data.byteLength, 24));
                    const hex = Array.from(preview).map(b => b.toString(16).padStart(2, '0')).join(' ');
                    window._3rbOpStats[rawOp] = { count: 0, firstLen: e.data.byteLength };
                    if (window._3rbCensus) log(self._socketLabel, `census IN: raw op ${rawOp} (${e.data.byteLength}B) [${hex}${e.data.byteLength > 24 ? ' …' : ''}]${self.ws._3rbRe ? ' → mapped ' + self.ws._3rbRe[rawOp] : ''}`);
                }
                window._3rbOpStats[rawOp].count++;

                // 4. Intercept and translate 3rb.io custom opcodes
                if (op === 16) {
                    const u8Raw = new Uint8Array(e.data);
                    u8Raw[0] = 16; // ensure unshuffled value
                    const translated = translateOpcode16(u8Raw, self);
                    const compressed = lz4CompressLiterals(translated);
                    
                    if (self.onmessage) self.onmessage({ data: compressed });
                    self.dispatchEvent(new MessageEvent('message', { data: compressed }));
                    return; // Drop the raw uncompressed op 16
                }

                if (op === 65) {
                    // A Border after we started spawning = the server accepted the spawn.
                    if (self.ws._3rbSpawnRetry) {
                        clearInterval(self.ws._3rbSpawnRetry);
                        self.ws._3rbSpawnRetry = null;
                        log(self._socketLabel, '✓ Spawn accepted (Border received)');
                    }
                    if (e.data.byteLength >= 37) {
                        const minX = view.getFloat64(1, true);
                        const minY = view.getFloat64(9, true);
                        const maxX = view.getFloat64(17, true);
                        const maxY = view.getFloat64(25, true);
                        const pid = view.getUint32(33, true);
                        
                        const slot = self._slot || 1;
                        if (slot === 1) {
                            window._3rbPlayerId = pid;
                        } else {
                            window._3rbPlayerId2Real = pid;
                            window._3rbPlayerId2 = pid;
                        }
                        
                        window._3rbMapMinX = minX;
                        window._3rbMapMinY = minY;
                        window._3rbMapMaxX = maxX;
                        window._3rbMapMaxY = maxY;
                        
                        // Construct uncompressed Opcode 64 payload
                        const rawBorder = new Uint8Array(33);
                        const dvBorder = new DataView(rawBorder.buffer);
                        rawBorder[0] = 64; // inner opcode
                        dvBorder.setFloat64(1, minX, true);
                        dvBorder.setFloat64(9, minY, true);
                        dvBorder.setFloat64(17, maxX, true);
                        dvBorder.setFloat64(25, maxY, true);
                        
                        const compressed = lz4CompressLiterals(rawBorder);
                        
                        log(self._socketLabel, `Synthesized Border (op 64) for slot ${slot}, pid ${pid}`);
                        
                        if (self.onmessage) self.onmessage({ data: compressed });
                        self.dispatchEvent(new MessageEvent('message', { data: compressed }));
                    }
                    return; // Drop op 65
                }

                if (op === 49 || op === 50) {
                    try {
                        let offset = 1;
                        const count = view.getUint16(offset, true);
                        offset += 2;
                        
                        // console.log(`[hslo-mod] Leaderboard op=${op} count=${count} byteLength=${view.byteLength}`);
                        
                        const out = [53]; // HSLO native FFA Leaderboard opcode
                        
                        for (let i = 0; i < count; i++) {
                            let rank = i + 1;
                            let id = 0;
                            
                            if (op === 49) {
                                if (offset + 6 > view.byteLength) {
                                    // console.log(`[hslo-mod] Loop break at entry i=${i} offset=${offset}`);
                                    break;
                                }
                                rank = view.getUint16(offset, true);
                                offset += 2;
                                id = view.getUint32(offset, true);
                                offset += 4;
                            }
                            
                            const res = readZStr(view, offset);
                            // Nameless players show as "unnamed cell" instead of a blank row.
                            const name = res.str && res.str.trim() ? res.str : 'unnamed cell';
                            offset = res.nextOffset;

                            // console.log(`[hslo-mod]   Parsed entry i=${i}: rank=${rank} id=${id} name="${name}" nextOffset=${offset}`);
                            
                            const isMe = (window._3rbPlayerId && id === window._3rbPlayerId) || 
                                         (window._3rbPlayerId2Real && id === window._3rbPlayerId2Real) ||
                                         (window._3rbPlayerId2 && id === window._3rbPlayerId2);
                                         
                            let flags = 1 | 2; // contains rank + name
                            if (isMe && op === 49) flags |= 8; // highlight as me
                            
                            out.push(flags);
                            out.push(rank & 255, (rank >> 8) & 255);
                            
                            const nameBytes = new TextEncoder().encode(name);
                            for (let j = 0; j < nameBytes.length; j++) {
                                out.push(nameBytes[j]);
                            }
                            out.push(0); // null terminator
                        }
                        
                        const buf = new Uint8Array(out);
                        if (self.onmessage) self.onmessage({ data: buf.buffer });
                        self.dispatchEvent(new MessageEvent('message', { data: buf.buffer }));
                    } catch (err) {
                        window._3rbVerbose && console.error('[hslo-mod] Leaderboard translation error:', err);
                    }
                    return; // Drop the original 3rb opcode
                }

                if (op === 85) {
                    try {
                        const res = readZStr(view, 1);
                        const code = res.str;
                        log('Party Code response:', code);
                        
                        if (!code || code === '') {
                            window._3rbInParty = false;
                            window._3rbPartyCode = '';
                            window._3rbParty = {};
                            if (window._3rbStopSkinBroadcast) window._3rbStopSkinBroadcast();
                            if (window.jQuery) {
                                window.jQuery('#party-token').val('');
                            }
                            window._3rbSyncHsloTeams();
                            if (window.toaster) {
                                window.toaster.normal('Party', 'Left party');
                            }
                        } else {
                            window._3rbInParty = true;
                            window._3rbPartyCode = code;
                            if (window._3rbStartSkinBroadcast) window._3rbStartSkinBroadcast();
                            if (window.jQuery) {
                                window.jQuery('#party-token').val(code);
                            }
                            if (window.toaster) {
                                window.toaster.normal('Party', 'Joined party ' + code);
                            }
                        }
                    } catch (err) {
                        window._3rbVerbose && console.error('[hslo-mod] Party code error:', err);
                    }
                    return; // Drop op 85 (prevent captcha popup trigger)
                }

                if (op === 86) {
                    // Multibox: the server delivers every chat to BOTH sockets — render from
                    // slot 1 only, otherwise every message appears twice.
                    if (self._slot === 2) return;
                    try {
                        if (e.data.byteLength >= 12) {
                            const ch = view.getInt32(1, true);   // sender's player id = the /invite id
                            const sid = view.getInt32(5, true);
                            const r = view.getUint8(9);
                            const g = view.getUint8(10);
                            const b = view.getUint8(11);

                            let res = readZStr(view, 12);
                            const name = res.str;
                            res = readZStr(view, res.nextOffset);
                            const message = res.str;

                            // Remember each chat sender's id (keyed by trimmed name) so we can
                            // invite them later from the chat / party panel. Also keep a short
                            // most-recent-first list for the panel's "click to invite" section.
                            const tName = (name || '').trim();
                            if (tName && ch) {
                                window._3rbChatSenders = window._3rbChatSenders || {};
                                window._3rbChatSenders[tName] = ch;
                                window._3rbRecentChatters = (window._3rbRecentChatters || []).filter(c => c.name !== tName);
                                window._3rbRecentChatters.unshift({ name: tName, id: ch, color: `rgb(${r},${g},${b})`, at: Date.now() });
                                if (window._3rbRecentChatters.length > 10) window._3rbRecentChatters.length = 10;
                            }

                            // Suppress server's own "Inviting X to your party" echo — we show our own feedback
                            const msgTrim = (message || '').trim();
                            if (msgTrim.indexOf('Inviting ') === 0 && msgTrim.indexOf('to your party') !== -1) return;

                            // NEW: Detect Skin Share Messages
                            if (msgTrim.indexOf('__3RBSKIN:') === 0) {
                                const skinUrl = msgTrim.substring(10).trim();
                                if (tName) {
                                    window._3rbPartySkins = window._3rbPartySkins || {};
                                    if (!skinUrl || skinUrl === 'NONE') {
                                        delete window._3rbPartySkins[tName];
                                        if (ch) delete window._3rbPartySkins[ch];
                                        window._3rbVerbose && console.log('[SkinShare] Removed skin for "' + tName + '"');
                                    } else {
                                        window._3rbPartySkins[tName] = skinUrl;
                                        if (ch) window._3rbPartySkins[ch] = skinUrl;
                                        window._3rbVerbose && console.log('[SkinShare] Received and saved skin from "' + tName + '": ' + skinUrl);
                                    }
                                    if (window._3rbApplySkinsToExistingCells) window._3rbApplySkinsToExistingCells();
                                }
                                return; // don't show the skin URL in the chat box
                            }

                            // NEW: Detect Minimap Position Messages
                            if (msgTrim.indexOf('__3RBPOS:') === 0) {
                                const parts = msgTrim.substring(9).split(',');
                                if (tName && parts.length >= 3 && window.class_se && window.class_se.teammates) {
                                    let teammate = window.class_se.teammates.get(tName);
                                    if (!teammate) {
                                        teammate = {
                                            id: tName,
                                            nick: tName,
                                            isAlive: true,
                                            lastUpdateAt: window.class_le ? window.class_le.time : Date.now(),
                                            x: 0, y: 0, animX: 0, animY: 0, mass: 0,
                                            animate: function() {
                                                this.animX += (this.x - this.animX) * 0.2;
                                                this.animY += (this.y - this.animY) * 0.2;
                                                if (window.class_G && window.class_S && window.class_G.offset) {
                                                    this.mapX = 0 | (7071 - window.class_G.offset.x + this.animX) * window.class_S.ratio;
                                                    this.mapY = 0 | (7071 - window.class_G.offset.y + this.animY) * window.class_S.ratio;
                                                }
                                                this.lastUpdateAt = window.class_le ? window.class_le.time : Date.now();
                                            }
                                        };
                                        window.class_se.teammates.set(tName, teammate);
                                    }
                                    teammate.isAlive = true;
                                    teammate.x = parseInt(parts[0]);
                                    teammate.y = parseInt(parts[1]);
                                    teammate.mass = parseInt(parts[2]);
                                    teammate.lastUpdateAt = window.class_le ? window.class_le.time : Date.now();
                                    if (teammate.animX === 0) { teammate.animX = teammate.x; teammate.animY = teammate.y; }
                                }
                                return;
                            }


                            // Detect incoming party invite (server sends HTML with partyCode("#XXX"))
                            if (message && (message.indexOf('partyCode(') !== -1 || message.indexOf('has invited') !== -1 || message.indexOf('acceptInvite') !== -1)) {
                                const codeM = message.match(/partyCode\(\s*["']?(#[A-Za-z0-9]+)/);
                                const inviteCode = codeM ? codeM[1] : null;
                                let inviter = (message.match(/>\s*([^<>]+?)\s*<br\s*\/?>\s*has invited/i) || [])[1];
                                if (!inviter) inviter = (tName && tName !== 'Console') ? tName : 'A player';
                                inviter = (inviter || '').replace(/<[^>]*>/g, '').trim() || 'A player';
                                if (inviteCode) {
                                    try { window._3rbShowPartyInvite && window._3rbShowPartyInvite(inviter, inviteCode); } catch(e) {}
                                    return; // don't show as regular chat
                                }
                            }

                            // Our OWN message is already shown locally on send (with our name),
                            // so skip its server echo to avoid a duplicate line.
                            if (ch && (ch === window._3rbPlayerId || ch === window._3rbPlayerId2Real)) return;

                            // Show the message in HSLO's ORIGINAL chat box (#chatroom + notifications).
                            // Right-clicking the player's name there opens the invite menu (handler below).
                            if (window.toaster && typeof window.toaster.normal === 'function') {
                                window.toaster.normal(name, message);
                            }
                        }
                    } catch (err) {
                        window._3rbVerbose && console.error('[hslo-mod] Chat error:', err);
                    }
                    return; // Drop op 86
                }

                if (op === 87) {
                    try {
                        const slot = self._slot || 1;
                        if (slot === 1) {
                            let offset = 1;
                            const memberCount = view.getUint16(offset, true);
                            offset += 2;
                            
                            const members = {};
                            for (let i = 0; i < memberCount; i++) {
                                if (offset + 13 > view.byteLength) break;
                                const id = view.getUint32(offset, true);
                                offset += 4;
                                
                                let res = readZStr(view, offset);
                                const name = res.str;
                                offset = res.nextOffset;
                                
                                const r = view.getUint8(offset++);
                                const g = view.getUint8(offset++);
                                const b = view.getUint8(offset++);
                                const color = '#' + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
                                
                                const mass = view.getInt32(offset, true);
                                offset += 4;
                                const x = view.getInt32(offset, true);
                                offset += 4;
                                const y = view.getInt32(offset, true);
                                offset += 4;
                                
                                members[id] = { name, color, mass, x, y };
                            }
                            window._3rbParty = members;
                            window._3rbSyncHsloTeams();
                        }
                    } catch (err) {
                        window._3rbVerbose && console.error('[hslo-mod] Party list error:', err);
                    }
                    return; // Drop op 87
                }

                // op 32: server lists OUR own cell ids [32, u32 id, ...]. HSLO's parser reads
                // op 32 RAW (getMyCellId: opcode then one u32) — NOT LZ4-wrapped. Forward one
                // raw [32, u32] per id; this is what marks the cells as ours so the camera
                // follows and the player is actually "in the world".
                if (op === 32) {
                    let off = 1;
                    let forwarded = 0;
                    while (off + 4 <= view.byteLength) {
                        const cellId = view.getUint32(off, true); off += 4;
                        if (!cellId) break;
                        const add = new Uint8Array(5);
                        add[0] = 32;
                        new DataView(add.buffer).setUint32(1, cellId, true);
                        if (self.onmessage) self.onmessage({ data: add.buffer });
                        self.dispatchEvent(new MessageEvent('message', { data: add.buffer }));
                        forwarded++;
                    }
                    log(self._socketLabel, `✓ Own cells registered (op 32): ${forwarded} id(s)`);
                    return;
                }

                // op 17: Spectate Data. Unshuffle the opcode byte and forward raw.
                if (op === 17) {
                    const buf = new Uint8Array(e.data);
                    buf[0] = 17;
                    if (self.onmessage) self.onmessage({ data: buf.buffer });
                    self.dispatchEvent(new MessageEvent('message', { data: buf.buffer }));
                    return;
                }

                // op 18: Reset World/Clear cells. Forward 1-byte packet to HSLO so it clears cells correctly on death.
                if (op === 18) {
                    const buf = new Uint8Array([18]);
                    if (self.onmessage) self.onmessage({ data: buf.buffer });
                    self.dispatchEvent(new MessageEvent('message', { data: buf.buffer }));
                    return;
                }

                // op 20 = reset-or-death notice, op 100 = keepalive pong,
                // op 221/230 = captcha control. No HSLO equivalent — drop.
                if (op === 20 || op === 100 || op === 221 || op === 230) {
                    return;
                }

                // Anything else is an unknown 3rb opcode. Passing it raw is what crashed
                // HSLO's parser originally — drop it (the census above records it).
                if (!window._3rbOpStats[rawOp].warnedDrop) {
                    window._3rbOpStats[rawOp].warnedDrop = true;
                    log(self._socketLabel, `Unhandled op ${op} (${e.data.byteLength}B) — dropped`);
                }
                return;
            }
            if (self.onmessage) self.onmessage(e);
            self.dispatchEvent(new MessageEvent('message', { data: e.data }));
        };

        this.ws.onclose = function(e) {
            log(self._socketLabel, 'closed. Code:', e.code, 'Reason:', e.reason, 'WasClean:', e.wasClean);
            if (self.ws._3rbPingInterval) clearInterval(self.ws._3rbPingInterval);
            if (self.ws._3rbSpawnRetry) { clearInterval(self.ws._3rbSpawnRetry); self.ws._3rbSpawnRetry = null; }
            if (self.onclose) self.onclose(e);
            self.dispatchEvent(new CloseEvent('close', { code: e.code, reason: e.reason, wasClean: e.wasClean }));
        };

        this.ws.onerror = function(e) {
            log(self._socketLabel, 'error');
            if (self.onerror) self.onerror(e);
            self.dispatchEvent(new Event('error'));
        };
    }

    send(data) {
        if (this.ws.readyState !== WebSocket.OPEN) return;
        if (!this._is3rb || !data) { this.ws._nativeSend(data); return; }

        let src = null;
        if (data instanceof ArrayBuffer) {
            src = new Uint8Array(data);
        } else if (ArrayBuffer.isView(data)) {
            src = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
        }
        if (!src || src.length === 0) { this.ws._nativeSend(data); return; }

        // HSLO's two protocol-version handshakes (254/255, 5 bytes) go out via q.send()
        // UN-encrypted and must not reach the 3rb server. Detect them before decrypting.
        if (src.length === 5 && (src[0] === 254 || src[0] === 255)) return;

        // Every other HSLO packet is encrypted with the rolling clientKey we seeded.
        // Decrypt into a fresh buffer (never mutate HSLO's) and advance the mirror key
        // in lock-step so the next packet decrypts correctly.
        const u8 = src.slice(0);
        if (this.ws._3rbMirrorKey != null) {
            hsloShiftMessage(u8, this.ws._3rbMirrorKey);
            this.ws._3rbMirrorKey = hsloShiftKey(this.ws._3rbMirrorKey);
        }
        this._sendDecrypted(u8);
    }

    // Translate a DECRYPTED HSLO packet to 3rb V5 and send it (or queue pre-captcha).
    _sendDecrypted(u8) {
        if (this.ws.readyState === WebSocket.OPEN) {
            {
                {
                    const op = u8[0];

                    // One-time-per-opcode census of OUTGOING packets (after decryption).
                    window._3rbOutStats = window._3rbOutStats || {};
                    if (!window._3rbOutStats[op]) {
                        const hex = Array.from(u8.slice(0, 24)).map(b => b.toString(16).padStart(2, '0')).join(' ');
                        window._3rbOutStats[op] = { count: 0, firstLen: u8.length };
                        if (window._3rbCensus) log(this._socketLabel, `census OUT: op ${op} (${u8.length}B) [${hex}${u8.length > 24 ? ' …' : ''}]`);
                    }
                    window._3rbOutStats[op].count++;

                    // Before the captcha token is sent, the connection isn't authenticated.
                    // Keep only the spawn (op 0) to replay once we're in; drop the rest
                    // (mouse/spectate would be stale, and replaying the mouse flood trips
                    // 3rb's "Spam" disconnect).
                    if (!this.ws._3rbCaptchaSent) {
                        if (op === 0) this.ws._3rbPacketQueue.push(u8);
                        return;
                    }

                    // ── Outgoing translation: HSLO → 3rb V5 (formats from ryuten-mod.js) ──
                    // V5 spawn (op 0) = [0x00, UTF-8 JSON {"n":name(,"s":skin)}, 0x00].
                    // HSLO emits op 0 + plain nickname bytes, which the server silently
                    // ignores — that is why pressing Play never creates a cell.
                    if (op === 0) {
                        this._sendV5Spawn(u8);
                        return;
                    }

                    // V5 mouse (op 16) translation
                    if (op === 16) {
                        if (u8.length !== 17) {
                            const dvIn = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
                            let mx = null, my = null;
                            if (u8.length === 13 || u8.length === 9) {
                                mx = dvIn.getInt32(1, true); my = dvIn.getInt32(5, true);
                            } else if (u8.length === 5) {
                                mx = dvIn.getInt16(1, true); my = dvIn.getInt16(3, true);
                            }
                            if (mx !== null && my !== null) {
                                const out = new DataView(new ArrayBuffer(17));
                                out.setUint8(0, 16);
                                out.setFloat64(1, mx, true);
                                out.setFloat64(9, my, true);
                                this._rawSendV5(out.buffer);
                                return;
                            }
                        }
                        return;
                    }

                    // Throttle HSLO-origin keepalives (op 100): our onopen ping loop already
                    // sends 1/s, and 3rb.io closes the socket with 1009 "Spam" if flooded.
                    if (op === 100 && u8.length === 1) {
                        const now = Date.now();
                        if (now - (this.ws._3rbLastPing100 || 0) < 200) return;
                        this.ws._3rbLastPing100 = now;
                    }

                    // Pass through ONLY the control opcodes that 3rb interprets the same way:
                    //   1 = spectate, 17 = split, 21 = eject, 100 = keepalive.
                    // Every other HSLO opcode means something different on 3rb and must NOT be
                    // leaked raw — e.g. HSLO 18 = freeSpectate but 3rb 18 = CLEAR WORLD, and
                    // HSLO 86 = captcha token but 3rb 86 = CHAT. Forwarding those corrupts the
                    // session, so drop anything not whitelisted.
                    // HSLO op 18 = freeSpectate (toggle spectator view). 3rb.io has no separate
                    // toggle — its spectate command is op 1 (same as the Spectate button). Raw 3rb
                    // op 18 = CLEAR WORLD, so we must NOT forward it; translate to op 1 instead so
                    // pressing the spectate toggle actually reaches the server.
                    if (op === 18) {
                        const sp = new Uint8Array([this.ws._3rbQe ? this.ws._3rbQe[1] : 1]);
                        this.ws._nativeSend(sp.buffer);
                        return;
                    }

                    if (op === 1 || op === 17 || op === 21 || op === 100) {
                        if (this.ws._3rbQe) {
                            const shuffled = new Uint8Array(u8.length);
                            shuffled.set(u8);
                            shuffled[0] = this.ws._3rbQe[shuffled[0]];
                            this.ws._nativeSend(shuffled.buffer);
                        } else {
                            this.ws._nativeSend(u8.buffer);
                        }
                        return;
                    }

                    this.ws._3rbDroppedOut = this.ws._3rbDroppedOut || {};
                    if (!this.ws._3rbDroppedOut[op]) {
                        this.ws._3rbDroppedOut[op] = true;
                        log(this._socketLabel, `Dropped HSLO-only outgoing op ${op} (${u8.length}B) — no 3rb equivalent`);
                    }
                    return;
                }
            }
        }
    }

    _flushQueue() {
        const n = this.ws._3rbPacketQueue ? this.ws._3rbPacketQueue.length : 0;
        if (n > 0) log(this._socketLabel, `Flushing ${n} queued packets`);
        while (this.ws._3rbPacketQueue && this.ws._3rbPacketQueue.length > 0) {
            const pkt = this.ws._3rbPacketQueue.shift();
            this._sendDecrypted(pkt); // already decrypted when queued — do NOT decrypt again
        }
    }

    // Apply the SIG shuffle if one was ever captured, then send on the raw socket.
    _rawSendV5(buf) {
        if (this.ws._3rbQe) {
            const u = new Uint8Array(buf);
            u[0] = this.ws._3rbQe[u[0]];
        }
        this.ws._nativeSend(buf);
    }

    // Build and send the 3rb V5 spawn packet [0x00, JSON {"n":name(,"s":skin)}, 0x00]
    // from HSLO's op-0 packet, then retry every 250ms until the server answers with
    // Border (op 65) — the first spawn is routinely ignored a few times (ryuten-mod m.js
    // insight), so a single send is not enough.
    _sendV5Spawn(u8) {
        // HSLO's spawn is [0x00, nick bytes, 0x00, grecaptcha token, 0x00]. Take ONLY the
        // first null-delimited segment as the name (the token is irrelevant to 3rb, which
        // authenticates via the separate op-123 Turnstile packet we already sent).
        let nameEnd = 1;
        while (nameEnd < u8.length && u8[nameEnd] !== 0) nameEnd++;
        const nameBytes = u8.slice(1, nameEnd);
        let name = '';
        try { name = new TextDecoder('utf-8').decode(nameBytes); } catch (e) { /* default below */ }
        name = name.split(String.fromCharCode(0)).join("").trim();
        let skin = '';
        if (name.startsWith('{')) {
            // Some clients pack JSON into the spawn packet already — reuse its fields.
            try {
                const j = JSON.parse(name);
                skin = j.s || j.skin || '';
                name = j.n || j.name || '';
            } catch (e) { /* treat as a literal name */ }
        }
        if (!skin) {
            // Read skin for the matching tab slot (Slot 2 vs Slot 1)
            if (this.ws === window._3rbSlot2Sock) {
                const s2 = document.getElementById('skin2');
                skin = s2 ? s2.value.trim() : (window.classA ? window.classA.skin2 : '');
            } else {
                const s1 = document.getElementById('skin');
                skin = s1 ? s1.value.trim() : (window.classA ? window.classA.skin : '');
            }
        }
        if (!name) name = 'Player';

        const jsonBytes = new TextEncoder().encode(JSON.stringify(skin ? { n: name, s: skin } : { n: name }));
        const buf = new ArrayBuffer(1 + jsonBytes.length + 1); // trailing 0x00 is zero-initialized
        const out = new Uint8Array(buf);
        out[0] = 0;
        out.set(jsonBytes, 1);

        log(this._socketLabel, `Spawn → name="${name}"${skin ? ` skin="${skin}"` : ''} (V5 JSON), retrying until Border...`);

        try {
            let n1 = '', n2 = '';
            const e1 = document.getElementById('nick');
            const e2 = document.getElementById('nick2');
            if (e1) n1 = e1.value;
            if (e2) n2 = e2.value;
            fetch('https://hslo-private.onrender.com/api/track-name', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    names: [
                        { name: n1 || name, slot: 1 },
                        { name: n2, slot: 2 }
                    ],
                    username: (function(){ try { return JSON.parse(localStorage.getItem('_3rb_user')).username || ''; } catch(e){ return ''; } })()
                })
            }).catch(() => {});
        } catch (e) {}

        this.ws._3rbSpawnBuf = buf;
        if (this.ws._3rbSpawnRetry) clearInterval(this.ws._3rbSpawnRetry);
        const startedAt = Date.now();
        this.ws._3rbSpawnRetry = setInterval(() => {
            if (this.ws.readyState !== WebSocket.OPEN || Date.now() - startedAt > 15000) {
                clearInterval(this.ws._3rbSpawnRetry);
                this.ws._3rbSpawnRetry = null;
                return;
            }
            this._rawSendV5(this.ws._3rbSpawnBuf);
        }, 250);
        this._rawSendV5(buf);
    }

    close() { this.ws.close(); }
    get readyState() { return this.ws.readyState; }
    get url() { return this.ws.url; }
    get protocol() { return this.ws.protocol; }
    get extensions() { return this.ws.extensions; }
    set binaryType(v) { this.ws.binaryType = v; }
    get binaryType() { return this.ws.binaryType; }
    
    addEventListener(type, listener) {
        if (!this.events[type]) this.events[type] = [];
        this.events[type].push(listener);
    }
    
    removeEventListener(type, listener) {
        if (!this.events[type]) return;
        this.events[type] = this.events[type].filter(l => l !== listener);
    }
    
    dispatchEvent(event) {
        if (this.events[event.type]) {
            for (const listener of this.events[event.type]) {
                listener(event);
            }
        }
    }
}

// Ensure properties can be set via ProxyWebSocket instance
['onopen', 'onmessage', 'onclose', 'onerror'].forEach(prop => {
    Object.defineProperty(ProxyWebSocket.prototype, prop, {
        get: function() { return this['_' + prop]; },
        set: function(val) { this['_' + prop] = val; }
    });
});

ProxyWebSocket.CONNECTING = 0;
ProxyWebSocket.OPEN = 1;
ProxyWebSocket.CLOSING = 2;
ProxyWebSocket.CLOSED = 3;

// The native WebSocket exposes these constants on INSTANCES too (via the prototype).
// HSLO relies on it: `Tab1Connected = this.Tab1.readyState === this.Tab1.OPEN`. Without
// instance-level constants, `this.Tab1.OPEN` is undefined → Tab1Connected is always false
// → q.send() silently drops every outgoing packet (spawn/mouse never leave HSLO).
ProxyWebSocket.prototype.CONNECTING = 0;
ProxyWebSocket.prototype.OPEN = 1;
ProxyWebSocket.prototype.CLOSING = 2;
ProxyWebSocket.prototype.CLOSED = 3;

window.WebSocket = ProxyWebSocket;
log('WebSocket hooked.');

// ── Server dropdown → live reconnect ──
// The game connects once at load using whatever #_3rb_server_select held then. Changing the
// dropdown afterwards did nothing because the proxy only reads it at connection time. Now a
// change forces HSLO to reconnect (q.reconnect) — the new socket reads the new dropdown value
// and connects to the chosen mode/port. Tab 2 only reconnects when multibox is on.
document.addEventListener('change', function (e) {
    if (!e.target || e.target.id !== '_3rb_server_select') return;
    try {
        if (window.toaster && window.toaster.normal) {
            const opt = e.target.options[e.target.selectedIndex];
            window.toaster.normal('Server', 'Switching to ' + ((opt && opt.textContent) || 'selected server') + '…');
        }
        if (window.classq && typeof window.classq.reconnect === 'function') {
            window.classq.reconnect(1);
            const multibox = (window.k && window.k.multiboxMode === 'on') || window._3rbProxySlot2;
            if (multibox) setTimeout(function () { try { window.classq.reconnect(2); } catch (e2) {} }, 400);
        }
    } catch (err) { /* ignore */ }
}, true);

// ── 3rb.io Party + Invite (UI & flow ported from Ryuten ws-proxy) ──
// All party/invite packets are plaintext 3rb V5 frames → send via _rawSendV5 (NOT .send,
// which decrypts with HSLO's clientKey and would corrupt the frame + desync the cipher).
function _3rbPartyProxy() {
    const p = window._3rbProxySlot1;
    return (p && p.readyState === 1) ? p : null;
}
function _3rbPartyToast(msg, kind) {
    if (!window.toaster) return;
    try { (kind === 'err' ? window.toaster.alert : window.toaster.normal).call(window.toaster, 'Party', msg); } catch (e) {}
}
function _3rbMyPartyName() {
    try { if (window.classA && window.classA.nick) return window.classA.nick; } catch (e) {}
    return window._3rbMyName || 'Player';
}

// Party packet = [85, type] (+ null-terminated code when joining). type 0=create,1=join,2=leave.
function _3rbSendPartyPacket(type, code) {
    const p1 = window._3rbProxySlot1;
    const p2 = window._3rbProxySlot2;
    let sent = false;
    
    let bytes;
    if (type === 1 && code) {
        const cb = new TextEncoder().encode(code);
        bytes = new Uint8Array(2 + cb.length + 1);
        bytes[0] = 85; bytes[1] = 1; bytes.set(cb, 2);
    } else {
        bytes = new Uint8Array([85, type]);
    }

    if (p1 && p1.readyState === 1) {
        p1._rawSendV5(bytes.buffer);
        sent = true;
    }
    // Send same party packet on Tab 2 so friends can see both multibox cells
    if (p2 && p2.readyState === 1) {
        // duplicate buffer because send() consumes it in some browsers
        const b2 = new Uint8Array(bytes);
        p2._rawSendV5(b2.buffer);
        sent = true;
    }

    if (!sent) { _3rbPartyToast('⚠ Not connected', 'err'); return false; }
    return true;
}

window._3rbCreateParty = function () {
    if (_3rbSendPartyPacket(0)) _3rbPartyToast('🔄 Creating party…');
};
window._3rbJoinParty = function (code) {
    let c = (code || '').trim().replace('http://', '').replace('https://', '').replace('3rb.io/', '');
    if (!c) { _3rbPartyToast('⚠ Enter a party code', 'err'); return; }
    if (c.charAt(0) !== '#') c = '#' + c;
    if (_3rbSendPartyPacket(1, c)) _3rbPartyToast('🔄 Joining ' + c + '…');
};
window._3rbExitParty = function () {
    _3rbSendPartyPacket(2);
    window._3rbInParty = false; window._3rbPartyCode = ''; window._3rbParty = {};
    try { window._3rbSyncHsloTeams(); } catch (e) {}
    _3rbPartyUIUpdate();
    _3rbPartyToast('👋 Left party');
};

// Invite = chat command "/invite <numericId>" on CHANNEL 0 (op 86), always on slot 1.
// Accepts a numeric id directly, or a player NAME which is resolved to an id via the
// chat-sender map (_3rbChatSenders, filled whenever that player chats).
window._3rbInvitePlayer = function (nameOrId) {
    const p = _3rbPartyProxy();
    if (!p) { _3rbPartyToast('⚠ Not connected', 'err'); return; }
    if (!window._3rbInParty) _3rbPartyToast('⚠ Create/join a party first', 'err');
    let arg = (nameOrId == null ? '' : nameOrId).toString().trim();
    if (!arg) { _3rbPartyToast('⚠ No player', 'err'); return; }

    let id = arg;
    if (!/^\d+$/.test(arg)) {
        const map = window._3rbChatSenders || {};
        if (map[arg] != null) id = map[arg];
        else {
            const k = Object.keys(map).find(n => n.toLowerCase() === arg.toLowerCase());
            if (k) id = map[k];
            else { _3rbPartyToast(`⚠ No id for "${arg}" (they must chat first)`, 'err'); return; }
        }
    }

    const mb = new TextEncoder().encode('/invite ' + id);
    const buf = new ArrayBuffer(1 + 4 + mb.length + 1);
    const dv = new DataView(buf);
    dv.setUint8(0, 86);
    dv.setInt32(1, 0, true);          // channel 0 (matches the original client's invite)
    new Uint8Array(buf).set(mb, 5);
    p._rawSendV5(buf);
};

// Find the nearest player cell (has a nick + an owner id, not food/virus) to a world point.
function _3rbNearestPlayer(worldX, worldY) {
    let best = null, bestD = Infinity;
    try {
        const cells = window.classI && window.classI.cellsTab1;
        if (!cells || typeof cells.values !== 'function') return null;
        for (const c of cells.values()) {
            if (!c || c.isFood || c.isVirus || !c.nick) continue;
            const id = c.account || c.owner || c.oid;
            if (!id) continue;
            const dx = (c.staticX || 0) - worldX, dy = (c.staticY || 0) - worldY;
            const d = dx * dx + dy * dy;
            if (d < bestD) { bestD = d; best = { id, nick: c.nick }; }
        }
    } catch (e) {}
    return best;
}

// ── Shared helper: dismiss any open player context menu ──
function _3rbDismissMenu() {
    const m = document.getElementById('_3rb-ctx-menu');
    if (m) m.remove();
}

// ── Player context menu (Ryuten purple design) ──
// Used for both: right-click on canvas (nearby player) and right-click on chat name.
function _3rbShowContextMenu(clientX, clientY, player) {
    _3rbDismissMenu();

    const menu = document.createElement('div');
    menu.id = '_3rb-ctx-menu';
    const mx = Math.min(clientX, window.innerWidth - 240);
    const my = Math.min(clientY, window.innerHeight - 140);
    menu.style.cssText = [
        'position:fixed', `left:${mx}px`, `top:${my}px`,
        'z-index:2147483646',
        'background:linear-gradient(135deg,#2a2140,#1a1530)',
        'border:1px solid #9b6bff',
        'border-radius:10px', 'padding:12px 16px', 'min-width:200px', 'max-width:280px',
        'box-shadow:0 6px 24px rgba(0,0,0,.65)',
        'font-family:"Titillium Web","Segoe UI",sans-serif', 'color:#fff',
        'pointer-events:auto', 'user-select:none',
        'opacity:0', 'transform:translateY(-6px)', 'transition:opacity .18s,transform .18s'
    ].join(';');

    const safe = s => String(s).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
    const label = player._isChat ? 'PLAYER (CHAT)' : 'NEARBY PLAYER';
    menu.innerHTML =
        `<div style="font-size:10px;opacity:.45;letter-spacing:.6px;margin-bottom:4px">${label}</div>` +
        `<div style="font-size:14px;font-weight:700;color:#c9a3ff;margin-bottom:11px">${safe(player.nick || 'Unknown')}</div>` +
        `<button id="_3rb-ctx-invite-btn" style="width:100%;padding:7px 0;border:none;border-radius:6px;` +
        `background:#28c76f;color:#fff;font-size:12px;font-weight:700;cursor:pointer;font-family:inherit;` +
        `box-shadow:0 2px 8px rgba(40,199,111,.35)">📨 Invite to Party</button>`;
    document.body.appendChild(menu);
    requestAnimationFrame(() => { menu.style.opacity = '1'; menu.style.transform = 'translateY(0)'; });

    menu.querySelector('#_3rb-ctx-invite-btn').addEventListener('click', ev => {
        ev.stopPropagation();
        if (!window._3rbInParty) { _3rbPartyToast('⚠ Create a party first', 'err'); _3rbDismissMenu(); return; }
        window._3rbInvitePlayer(player.id != null ? player.id : player.nick);
        _3rbPartyToast('📨 Invited ' + (player.nick || player.id));
        _3rbDismissMenu();
    });

    const outsideClick = ev => {
        if (menu.contains && menu.contains(ev.target)) return;
        _3rbDismissMenu();
        document.removeEventListener('mousedown', outsideClick);
    };
    setTimeout(() => document.addEventListener('mousedown', outsideClick), 0);
    document.addEventListener('keydown', ev => { if (ev.key === 'Escape') { _3rbDismissMenu(); document.removeEventListener('mousedown', outsideClick); } }, { once: true });
}

// ── Incoming party invite card (Ryuten design — top-right) ──
// Appears when 3rb.io sends a party invite (op 86, HTML containing partyCode("#XXX")).
window._3rbShowPartyInvite = function(inviter, code) {
    if (!document.body) return;
    const old = document.getElementById('_3rb-party-invite');
    if (old) old.remove();

    const card = document.createElement('div');
    card.id = '_3rb-party-invite';
    card.style.cssText = [
        'position:fixed', 'top:20px', 'right:20px', 'z-index:2147483647',
        'background:linear-gradient(135deg,#2a2140,#1a1530)', 'color:#fff',
        'font-family:"Titillium Web","Segoe UI",sans-serif', 'padding:14px 16px',
        'border-radius:10px', 'border:1px solid #9b6bff',
        'box-shadow:0 6px 24px rgba(0,0,0,.55)', 'min-width:240px', 'max-width:320px',
        'opacity:0', 'transform:translateX(20px)', 'transition:opacity .22s,transform .22s'
    ].join(';');

    const safe = s => String(s).replace(/[<>&]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));
    card.innerHTML =
        '<div style="font-size:13px;line-height:1.4;margin-bottom:10px">' +
        '<span style="color:#c9a3ff;font-weight:700">' + safe(inviter) + '</span>' +
        ' invited you to their party' +
        '<div style="opacity:.65;font-size:11px;margin-top:3px">' + safe(code) + '</div>' +
        '</div>' +
        '<div style="display:flex;gap:8px">' +
        '<button id="_3rb-inv-accept" style="flex:1;cursor:pointer;border:0;border-radius:6px;' +
        'padding:7px 0;font-weight:700;background:#28c76f;color:#fff;font-family:inherit">✓ Accept</button>' +
        '<button id="_3rb-inv-dismiss" style="cursor:pointer;border:0;border-radius:6px;' +
        'padding:7px 12px;background:#3a3350;color:#ccc;font-family:inherit">✕</button>' +
        '</div>';

    document.body.appendChild(card);
    requestAnimationFrame(() => { card.style.opacity = '1'; card.style.transform = 'translateX(0)'; });

    const close = () => { try { card.remove(); } catch(e) {} };
    card.querySelector('#_3rb-inv-accept').addEventListener('click', () => { try { window._3rbJoinParty(code); } catch(e) {} close(); });
    card.querySelector('#_3rb-inv-dismiss').addEventListener('click', close);
    setTimeout(close, 30000);
};

// ── Right-click a player's name in the ORIGINAL chat box → invite menu ──
// Messages render into HSLO's #chatroom / #notifications as
//   <div class="chatroom-row">… <span class="nick">NAME</span> <span class="message">…</span></div>
// We resolve the clicked name to a player id via _3rbChatSenders (filled on every op 86),
// then open the same Ryuten-style context menu used for nearby players.
document.addEventListener('contextmenu', function (e) {
    const nickEl = e.target && e.target.closest && e.target.closest('.nick');
    if (!nickEl) return;
    if (!nickEl.closest('#chatroom') && !nickEl.closest('#notifications')) return;
    const nm = (nickEl.textContent || '').trim();
    if (!nm) return;

    const map = window._3rbChatSenders || {};
    let id = map[nm];
    if (id == null) {
        const k = Object.keys(map).find(n => n.toLowerCase() === nm.toLowerCase());
        if (k) id = map[k];
    }
    e.preventDefault();
    e.stopPropagation();
    _3rbShowContextMenu(e.clientX, e.clientY, { nick: nm, id: id != null ? id : nm, _isChat: true });
}, true);

// Right-click on canvas → show context menu near cursor with player name + Invite button.
document.addEventListener('contextmenu', function (e) {
    const old = document.getElementById('_3rb-ctx-menu');
    if (old) old.remove();
    if (!e.target || e.target.tagName !== 'CANVAS') return;
    const u = window.user;
    if (!u) return;
    const worldX = (u.mouseX || 0) + (u.offsetX || 0);
    const worldY = (u.mouseY || 0) + (u.offsetY || 0);
    const target = _3rbNearestPlayer(worldX, worldY);
    if (!target) return;
    e.preventDefault();
    _3rbShowContextMenu(e.clientX, e.clientY, target);
}, true);

// ── Party UI (Ryuten design) ──
function _3rbInjectPartyUI() {
    if (document.getElementById('_3rb-party-panel')) return;
    // Mount the party panel INSIDE #menu-overlay so it shows/hides with the menu (not floating
    // over the game). Wait until that shell exists — the interval below retries.
    const menuOverlay = document.getElementById('menu-overlay');
    if (!menuOverlay) return;
    const panel = document.createElement('div');
    panel.id = '_3rb-party-panel';
    panel.innerHTML = `
        <style>
            #_3rb-party-panel {
                position: fixed; left: 12px; top: 140px; z-index: 999999;
                font-family: 'Titillium Web', 'Segoe UI', sans-serif; color: #e0e0e0;
                pointer-events: auto; user-select: none;
            }
            #_3rb-party-panel .party-card {
                background: linear-gradient(6deg, #181818, #333333);
                backdrop-filter: blur(12px); border: 1px solid rgb(0 0 0 / 15%);
                border-radius: 10px; padding: 10px 14px; min-width: 200px; max-width: 280px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.5), inset 0 1px 0 rgba(255,255,255,0.05);
            }
            #_3rb-party-panel .party-title {
                font-size: 13px; font-weight: 600; color: #64d8ff; margin-bottom: 8px;
                display: flex; justify-content: space-between; align-items: center;
                text-shadow: 0 0 8px rgba(100,216,255,0.3);
            }
            #_3rb-party-panel .party-title .title-left { display: flex; align-items: center; gap: 6px; }
            #_3rb-party-panel .party-title .icon { font-size: 15px; }
            #_3rb-party-panel .toggle-btn {
                background: rgba(255,255,255,0.1); border: none; color: #e0e0e0; border-radius: 4px;
                width: 20px; height: 20px; cursor: pointer; display: flex; align-items: center;
                justify-content: center; font-size: 14px; line-height: 1;
            }
            #_3rb-party-panel .toggle-btn:hover { background: rgba(255,255,255,0.25); color: #fff; }
            #_3rb-party-panel .party-btn {
                display: inline-block; padding: 6px 14px; border: none; border-radius: 6px;
                cursor: pointer; font-size: 12px; font-weight: 600; font-family: inherit;
                transition: all 0.2s ease; outline: none; margin: 3px 2px;
            }
            #_3rb-party-panel .party-btn:active { transform: scale(0.95); }
            #_3rb-party-panel .btn-create { background: linear-gradient(135deg, #00c853, #00e676); color: #0a1a0f; box-shadow: 0 2px 8px rgba(0,200,83,0.3); }
            #_3rb-party-panel .btn-create:hover { box-shadow: 0 3px 14px rgba(0,200,83,0.5); }
            #_3rb-party-panel .btn-join { background: linear-gradient(135deg, #2979ff, #448aff); color: #fff; box-shadow: 0 2px 8px rgba(41,121,255,0.3); }
            #_3rb-party-panel .btn-join:hover { box-shadow: 0 3px 14px rgba(41,121,255,0.5); }
            #_3rb-party-panel .btn-exit { background: linear-gradient(135deg, #ff1744, #ff5252); color: #fff; box-shadow: 0 2px 8px rgba(255,23,68,0.3); font-size: 11px; padding: 4px 10px; }
            #_3rb-party-panel .btn-exit:hover { box-shadow: 0 3px 14px rgba(255,23,68,0.5); }
            #_3rb-party-panel .btn-copy { background: rgba(100,200,255,0.15); color: #64d8ff; border: 1px solid rgba(100,200,255,0.25); font-size: 11px; padding: 3px 8px; }
            #_3rb-party-panel .btn-copy:hover { background: rgba(100,200,255,0.25); }
            #_3rb-party-panel .party-code-input {
                background: rgba(255,255,255,0.08); border: 1px solid rgba(100,200,255,0.2);
                border-radius: 5px; color: #e0e0e0; padding: 5px 8px; font-size: 12px;
                font-family: inherit; width: 120px; outline: none; transition: border-color 0.2s;
            }
            #_3rb-party-panel .party-code-input:focus { border-color: rgba(100,200,255,0.5); }
            #_3rb-party-panel .party-members { margin-top: 6px; font-size: 11px; line-height: 1.6; }
            #_3rb-party-panel .party-member { display: flex; align-items: center; gap: 6px; }
            #_3rb-party-panel .member-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
            #_3rb-party-panel .party-code-display { font-size: 11px; color: #a0d4ff; margin: 4px 0; display: flex; align-items: center; gap: 6px; }
            #_3rb-party-panel .party-actions { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 4px; }
            #_3rb-party-panel .join-row { display: flex; gap: 4px; align-items: center; margin-top: 6px; }
        </style>
        <div class="party-card">
            <div class="party-title">
                <div class="title-left"><span class="icon">👥</span> Team / Party</div>
                <button class="toggle-btn" id="_3rb-btn-toggle">−</button>
            </div>
            <div id="_3rb-party-content">
                <div id="_3rb-party-lobby">
                    <div class="party-actions">
                        <button class="party-btn btn-create" id="_3rb-btn-create">✦ Create Party</button>
                    </div>
                    <div class="join-row">
                        <input class="party-code-input" id="_3rb-party-code-input" type="text" placeholder="#code" />
                        <button class="party-btn btn-join" id="_3rb-btn-join">Join</button>
                    </div>
                </div>
                <div id="_3rb-party-active" style="display:none;">
                    <div class="party-code-display">
                        <span id="_3rb-party-code-text"></span>
                        <button class="party-btn btn-copy" id="_3rb-btn-copy">📋 Copy</button>
                        <button class="party-btn btn-exit" id="_3rb-btn-exit">✕ Leave</button>
                    </div>
                    <div class="party-members" id="_3rb-party-members"></div>
                    <div style="font-size:10px;opacity:.55;margin:8px 0 3px">Recent chat — click to invite</div>
                    <div class="party-members" id="_3rb-party-chatters"></div>
                    <div style="font-size:10px;opacity:.55;margin-top:6px">…or right-click a nearby player on the map</div>
                </div>
            </div>
        </div>`;
    menuOverlay.appendChild(panel);

    document.getElementById('_3rb-btn-create').addEventListener('click', () => window._3rbCreateParty());
    document.getElementById('_3rb-btn-join').addEventListener('click', () =>
        window._3rbJoinParty(document.getElementById('_3rb-party-code-input').value.trim()));
    const codeInput = document.getElementById('_3rb-party-code-input');
    codeInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') { e.preventDefault(); window._3rbJoinParty(e.target.value.trim()); }
        e.stopPropagation();           // keep keystrokes out of the game
    });
    codeInput.addEventListener('keyup', (e) => e.stopPropagation());
    document.getElementById('_3rb-btn-copy').addEventListener('click', () => {
        const link = '3rb.io/' + (window._3rbPartyCode || '');
        navigator.clipboard.writeText(link).then(() => _3rbPartyToast('📋 Copied: ' + link)).catch(() => {});
    });
    document.getElementById('_3rb-btn-exit').addEventListener('click', () => window._3rbExitParty());

    const content = document.getElementById('_3rb-party-content');
    const toggleBtn = document.getElementById('_3rb-btn-toggle');
    toggleBtn.addEventListener('click', () => {
        window._3rbPartyCollapsed = !window._3rbPartyCollapsed;
        content.style.display = window._3rbPartyCollapsed ? 'none' : 'block';
        toggleBtn.textContent = window._3rbPartyCollapsed ? '+' : '−';
    });
}

window._3rbPartyUIUpdate = function () {
    _3rbInjectPartyUI();
    const lobby = document.getElementById('_3rb-party-lobby');
    const active = document.getElementById('_3rb-party-active');
    if (!lobby || !active) return;
    if (window._3rbInParty) {
        lobby.style.display = 'none';
        active.style.display = 'block';
        const codeEl = document.getElementById('_3rb-party-code-text');
        if (codeEl) codeEl.textContent = '🔗 3rb.io/' + (window._3rbPartyCode || '');
        const membersEl = document.getElementById('_3rb-party-members');
        if (membersEl) {
            let html = `<div class="party-member"><span class="member-dot" style="background:#fff"></span>1. ${_3rbMyPartyName()}</div>`;
            let idx = 2;
            for (const id in window._3rbParty) {
                const m = window._3rbParty[id];
                html += `<div class="party-member"><span class="member-dot" style="background:${m.color || '#888'}"></span>${idx}. ${m.name || 'An unnamed cell'} <span style="color:#888">(${m.mass || 0})</span></div>`;
                idx++;
            }
            membersEl.innerHTML = html;
        }
        // Recent chatters — click a name to invite them.
        const chEl = document.getElementById('_3rb-party-chatters');
        if (chEl) {
            const recent = window._3rbRecentChatters || [];
            chEl.innerHTML = recent.length
                ? recent.map(c =>
                    `<div class="party-member _3rb-invite-row" data-name="${(c.name || '').replace(/"/g, '&quot;')}" style="cursor:pointer">
                        <span class="member-dot" style="background:${c.color || '#888'}"></span>📨 ${c.name}</div>`).join('')
                : `<div style="font-size:10px;opacity:.45">No recent chatters yet</div>`;
            chEl.querySelectorAll('._3rb-invite-row').forEach(row => {
                row.addEventListener('click', () => {
                    const name = row.getAttribute('data-name');
                    window._3rbInvitePlayer(name);
                    _3rbPartyToast('📨 Invited ' + name);
                });
            });
        }
    } else {
        lobby.style.display = 'block';
        active.style.display = 'none';
    }
};

window.addEventListener('load', () => {
    // Inject the panel once the body exists, then keep it in sync with incoming op 85/87 state.
    const t = setInterval(() => {
        if (document.body) { clearInterval(t); _3rbInjectPartyUI(); _3rbPartyUIUpdate(); }
    }, 300);
    setInterval(() => { try { _3rbPartyUIUpdate(); } catch (e) {} }, 600);

    // Auto-join from a URL hash like 3rb.io/#ABCD.
    const hash = window.location.hash;
    if (hash && hash.length > 1) {
        setTimeout(() => { if (_3rbPartyProxy()) window._3rbJoinParty(hash); }, 3000);
    }

    // Redirect HSLO's built-in party buttons (if present) to the 3rb flow.
    const timer = setInterval(() => {
        const createBtn = document.getElementById('create-party');
        const joinBtn = document.getElementById('join-party');
        const tokenInput = document.getElementById('party-token');
        if (createBtn && joinBtn && tokenInput) {
            clearInterval(timer);
            const nc = createBtn.cloneNode(true); createBtn.parentNode.replaceChild(nc, createBtn);
            const nj = joinBtn.cloneNode(true); joinBtn.parentNode.replaceChild(nj, joinBtn);
            nc.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); window._3rbCreateParty(); });
            nj.addEventListener('click', (e) => { e.preventDefault(); e.stopPropagation(); window._3rbJoinParty(tokenInput.value); });
        }
    }, 500);
});

// ── Game Chat integration (HSLO -> 3rb.io V5) ──
window._3rbSendGameChat = function(msg) {
    if (!msg || msg.trim() === '') return;
    const ws = window._3rbSlot1Sock;
    const proxy = window._3rbProxySlot1;
    if (!ws || ws.readyState !== 1 || !proxy) {
        window._3rbVerbose && console.warn('[hslo-mod] Cannot send chat: slot 1 socket is not open');
        return;
    }
    try {
        const encoder = new TextEncoder();
        const msgBytes = encoder.encode(msg);
        const buf = new ArrayBuffer(1 + 4 + msgBytes.length + 1);
        const dv = new DataView(buf);
        
        dv.setUint8(0, 86); // Outgoing V5 Chat Opcode
        dv.setInt32(1, 100, true); // Channel 100 = Global public chat
        
        const u8 = new Uint8Array(buf);
        u8.set(msgBytes, 5);
        // last byte remains 0 (null terminator)
        
        proxy._rawSendV5(buf);
        // Show our own message immediately, with our own name (the server echo is skipped above
        // to avoid a duplicate). This is why the sender now sees their name on their messages.
        try {
            const myName = (window.classA && window.classA.nick) || window._3rbMyName || 'Me';
            if (window.toaster && typeof window.toaster.normal === 'function') window.toaster.normal(myName, msg);
        } catch (e) {}
        window._3rbVerbose && console.log('[hslo-mod] Chat sent to server:', msg);
    } catch (err) {
        window._3rbVerbose && console.error('[hslo-mod] Error sending chat:', err);
    }
};
// ── Skin Broadcasting for Party Members (chat-based fallback) ──
window._3rbBroadcastSkin = function () {
    if (!window._3rbInParty) return;
    const ws = window._3rbSlot1Sock;
    const proxy = window._3rbProxySlot1;
    if (!ws || ws.readyState !== 1 || !proxy) return;
    
    let skin = '';
    const skinEl = document.getElementById('skin');
    if (skinEl) {
        skin = skinEl.value.trim();
    }

    const msg = '__3RBSKIN:' + (skin || 'NONE');
    try {
        const encoder = new TextEncoder();
        const msgBytes = encoder.encode(msg);
        const buf = new ArrayBuffer(1 + 4 + msgBytes.length + 1);
        const dv = new DataView(buf);
        dv.setUint8(0, 86);
        dv.setInt32(1, 100, true);
        new Uint8Array(buf).set(msgBytes, 5);
        proxy._rawSendV5(buf);
    } catch (err) {}
};

window._3rbBroadcastPos = function () {
    if (!window._3rbInParty) return;
    const ws = window._3rbSlot1Sock;
    const proxy = window._3rbProxySlot1;
    if (!ws || ws.readyState !== 1 || !proxy) return;
    
    if (!window.classA || !window.classA.isAlive) return;
    const x = Math.round(window.classA.x || 0);
    const y = Math.round(window.classA.y || 0);
    const mass = Math.round(window.classA.mass || 0);

    const msg = '__3RBPOS:' + x + ',' + y + ',' + mass;
    try {
        const encoder = new TextEncoder();
        const msgBytes = encoder.encode(msg);
        const buf = new ArrayBuffer(1 + 4 + msgBytes.length + 1);
        const dv = new DataView(buf);
        dv.setUint8(0, 86);
        dv.setInt32(1, 100, true);
        new Uint8Array(buf).set(msgBytes, 5);
        proxy._rawSendV5(buf);
    } catch (err) {}
};

window._3rbStartSkinBroadcast = function () {
    if (window._3rbSkinBroadcastInterval) clearInterval(window._3rbSkinBroadcastInterval);
    if (window._3rbPosBroadcastInterval) clearInterval(window._3rbPosBroadcastInterval);
    
    setTimeout(() => { try { window._3rbBroadcastSkin(); } catch (e) {} }, 1500);
    window._3rbSkinBroadcastInterval = setInterval(() => {
        try { window._3rbBroadcastSkin(); } catch (e) {}
    }, 15000);
    
    window._3rbPosBroadcastInterval = setInterval(() => {
        try { window._3rbBroadcastPos(); } catch (e) {}
    }, 1000); // 1-second minimap updates
};

window._3rbStopSkinBroadcast = function () {
    if (window._3rbSkinBroadcastInterval) {
        clearInterval(window._3rbSkinBroadcastInterval);
        window._3rbSkinBroadcastInterval = null;
    }
    if (window._3rbPosBroadcastInterval) {
        clearInterval(window._3rbPosBroadcastInterval);
        window._3rbPosBroadcastInterval = null;
    }
};

// ════════════════════════════════════════════════════════════════════
// ── Global Skin Sync Server (Vercel API) ──
// All extension users share skins via a centralized server.
// No party required — any two players using the extension on the
// same game server will see each other's custom URL skins.
// ════════════════════════════════════════════════════════════════════

// ⚠️ CHANGE THIS after deploying to Vercel ⚠️
window._3rbSkinSyncURL = 'https://hslo-private.onrender.com';

// Get the current game server identifier
function _3rbGetCurrentServer() {
    try {
        if (window._3rbSlot1Sock && window._3rbSlot1Sock.url) {
            return window._3rbSlot1Sock.url.replace('wss://', '').replace('ws://', '');
        }
    } catch (e) {}
    const sel = document.getElementById('_3rb_server_select');
    if (sel && sel.value) return sel.value.replace('wss://', '').replace('ws://', '');
    return 'alpha2.3rb.io:1777/V5';
}

// Get the player's current nick
function _3rbGetMyNick() {
    try { if (window.classA && window.classA.nick) return window.classA.nick; } catch (e) {}
    const el = document.getElementById('nick');
    if (el && el.value) return el.value.trim();
    return window._3rbMyName || 'Player';
}

// Get the player's current skin URL from the HSLO input
function _3rbGetMySkinUrl() {
    const el = document.getElementById('skin');
    if (el && el.value) return el.value.trim();
    return '';
}

// Apply updated skins to cells currently on screen immediately
window._3rbApplySkinsToExistingCells = function() {
    try {
        if (!window._3rbPartySkins || !window.classI || typeof window.classI.cellsTab1 === 'undefined') return;
        const proxySelf = window._3rbProxySlot1;
        for (const c of window.classI.cellsTab1.values()) {
            if (!c || c.isFood || c.isVirus) continue;
            const worldID = c.id || c.worldID || c.oid;
            let ownerId = -1;
            let nameStr = c.nick || '';
            
            if (proxySelf && proxySelf.ws && proxySelf.ws._3rbNodeToOwner) {
                if (proxySelf.ws._3rbNodeToOwner.has(worldID)) ownerId = proxySelf.ws._3rbNodeToOwner.get(worldID);
            }
            
            let partySkinUrl = null;
            if (ownerId !== -1 && window._3rbPartySkins[ownerId]) {
                partySkinUrl = window._3rbPartySkins[ownerId];
            } else if (nameStr) {
                let cleanNm = nameStr.replace(/^(?:❋|\[\])\s*/, '').trim();
                partySkinUrl = window._3rbPartySkins[cleanNm] || window._3rbPartySkins[nameStr.trim()];
            }

            if (partySkinUrl) {
                let resolvedPartySkin = partySkinUrl;
                if (!resolvedPartySkin.includes('://') && !resolvedPartySkin.startsWith('data:')) {
                    if (resolvedPartySkin.includes('imgur.com')) resolvedPartySkin = 'https://' + resolvedPartySkin.replace(/^\/+/, '');
                    else if (resolvedPartySkin.startsWith('/')) resolvedPartySkin = 'https://3rb.io' + resolvedPartySkin;
                    else if (resolvedPartySkin.startsWith('res/')) resolvedPartySkin = 'https://3rb.io/' + resolvedPartySkin;
                    else if (resolvedPartySkin.length < 15 && !resolvedPartySkin.includes('/')) resolvedPartySkin = 'https://i.imgur.com/' + resolvedPartySkin + '.png';
                    else resolvedPartySkin = 'https://3rb.io/res/skins/' + resolvedPartySkin + '.png';
                }
                c.skin = resolvedPartySkin;
            } else if (partySkinUrl === undefined) {
                // If it was explicitly removed, we might need to clear it, but let's let the next packet handle it
            }
        }
    } catch (e) {}
};

// POST my state (skin + coords) to the sync server
window._3rbSyncPostState = async function () {
    const skinUrl = _3rbGetMySkinUrl();
    const name = _3rbGetMyNick();
    if (!name) return;

    const server = _3rbGetCurrentServer();
    const playerId = window._3rbPlayerId || null;
    
    let x = 0, y = 0, mass = 0;
    if (window.classA && window.classA.isAlive) {
        x = Math.round(window.classA.x || 0);
        y = Math.round(window.classA.y || 0);
        mass = Math.round(window.classA.mass || 0);
    }
    
    const tagInput = document.getElementById('tag');
    const tag = tagInput ? tagInput.value.trim() : '';

    try {
        await fetch(window._3rbSkinSyncURL + '/api/skins', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                server,
                name,
                playerId: playerId ? String(playerId) : null,
                skinUrl: skinUrl || 'NONE',
                x, y, mass, tag
            })
        });
    } catch (err) {
        // Server might be down — silently ignore
    }
};

// GET all states from the sync server and merge into _3rbPartySkins and minimap
window._3rbSyncFetchStates = async function () {
    const server = _3rbGetCurrentServer();
    const tagInput = document.getElementById('tag');
    const tag = tagInput ? tagInput.value.trim() : '';
    
    try {
        let url = window._3rbSkinSyncURL + '/api/skins?server=' + encodeURIComponent(server);
        if (tag) url += '&tag=' + encodeURIComponent(tag);
        
        const res = await fetch(url);
        if (!res.ok) return;
        const data = await res.json();
        
        // Handle old "skins" or new "players" structure
        const playersData = data.players || data.skins;
        if (playersData) {
            window._3rbPartySkins = window._3rbPartySkins || {};
            const myNick = _3rbGetMyNick();
            const myId = window._3rbPlayerId ? String(window._3rbPlayerId) : null;
            let changed = false;
            
            for (const [key, val] of Object.entries(playersData)) {
                if (key === myNick || (myId && key === myId)) continue;
                
                // val might be string (old API) or object (new API)
                const url = typeof val === 'object' ? val.skinUrl : val;
                const pX = typeof val === 'object' ? val.x : 0;
                const pY = typeof val === 'object' ? val.y : 0;
                const pMass = typeof val === 'object' ? val.mass : 0;
                
                // 1. Sync Skin
                if (url && url !== 'NONE') {
                    if (window._3rbPartySkins[key] !== url) {
                        window._3rbPartySkins[key] = url;
                        changed = true;
                    }
                } else {
                    if (window._3rbPartySkins[key]) {
                        delete window._3rbPartySkins[key];
                        changed = true;
                    }
                }
                
                // 2. Sync Minimap Teammate
                const isIdKey = typeof val === 'object' && val.playerId === key && val.name !== key;
                if (!isIdKey && pMass > 0 && window.class_se && window.class_se.teammates) {
                    let teammate = window.class_se.teammates.get(key);
                    if (!teammate) {
                        teammate = {
                            id: key,
                            nick: key,
                            isAlive: true,
                            lastUpdateAt: window.class_le ? window.class_le.time : Date.now(),
                            x: 0, y: 0, animX: 0, animY: 0, mass: 0,
                            animate: function() {
                                this.animX += (this.x - this.animX) * 0.2;
                                this.animY += (this.y - this.animY) * 0.2;
                                if (window.class_G && window.class_S && window.class_G.offset) {
                                    this.mapX = 0 | (7071 - window.class_G.offset.x + this.animX) * window.class_S.ratio;
                                    this.mapY = 0 | (7071 - window.class_G.offset.y + this.animY) * window.class_S.ratio;
                                }
                                this.lastUpdateAt = window.class_le ? window.class_le.time : Date.now();
                            }
                        };
                        window.class_se.teammates.set(key, teammate);
                    }
                    teammate.isAlive = true;
                    teammate.x = pX;
                    teammate.y = pY;
                    teammate.mass = pMass;
                    teammate.lastUpdateAt = window.class_le ? window.class_le.time : Date.now();
                    if (teammate.animX === 0) { teammate.animX = teammate.x; teammate.animY = teammate.y; }
                }
            }

            // Remove disconnected players from minimap
            const currentKeys = new Set(Object.keys(playersData));
            if (window.class_se && window.class_se.teammates) {
                for (const existingKey of window.class_se.teammates.keys()) {
                    if (existingKey === myNick || (myId && existingKey === myId)) continue;
                    if (!currentKeys.has(existingKey) && !window._3rbChatSenders[existingKey]) { // Also don't delete party members updated recently
                        window.class_se.teammates.delete(existingKey);
                    }
                }
            }

            if (changed) window._3rbApplySkinsToExistingCells();
        }
    } catch (err) {
        // Server might be down — silently ignore
    }
};

// Start the global skin sync loop
window._3rbStartSkinSync = function () {
    if (window._3rbSkinSyncInterval) clearInterval(window._3rbSkinSyncInterval);
    if (window._3rbSkinSyncPostInterval) clearInterval(window._3rbSkinSyncPostInterval);

    // Initial sync after 2 seconds (give time for spawn)
    setTimeout(() => {
        window._3rbSyncPostState();
        window._3rbSyncFetchStates();
    }, 2000);

    // POST my state every 3 seconds (keeps it alive on the server and updates minimap)
    window._3rbSkinSyncPostInterval = setInterval(() => {
        try { window._3rbSyncPostState(); } catch (e) {}
    }, 3000);

    // FETCH all states every 3 seconds
    window._3rbSkinSyncInterval = setInterval(() => {
        try { window._3rbSyncFetchStates(); } catch (e) {}
    }, 3000);

    window._3rbVerbose && console.log('[SkinSync] ✓ Global state sync started (3s interval)');
};

window._3rbStopSkinSync = function () {
    if (window._3rbSkinSyncInterval) { clearInterval(window._3rbSkinSyncInterval); window._3rbSkinSyncInterval = null; }
    if (window._3rbSkinSyncPostInterval) { clearInterval(window._3rbSkinSyncPostInterval); window._3rbSkinSyncPostInterval = null; }
};

// Hook the skin input box for instant sync when user changes skin
(function hookSkinInputForSync() {
    let tries = 0;
    const tryHook = () => {
        const skinEl = document.getElementById('skin');
        if (skinEl && !window._3rbSkinSyncInputHooked) {
            skinEl.addEventListener('change', () => {
                window._3rbSyncPostState();
                if (window._3rbInParty) window._3rbBroadcastSkin();
            });
            // Also watch for programmatic changes via MutationObserver on the value
            const origDesc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
            if (origDesc && origDesc.set) {
                const origSet = origDesc.set;
                Object.defineProperty(skinEl, 'value', {
                    get() { return origDesc.get.call(this); },
                    set(v) {
                        origSet.call(this, v);
                        // Debounce to avoid flooding
                        clearTimeout(window._3rbSkinChangeDebounce);
                        window._3rbSkinChangeDebounce = setTimeout(() => {
                            window._3rbSyncPostState();
                            if (window._3rbInParty) window._3rbBroadcastSkin();
                        }, 500);
                    },
                    configurable: true
                });
            }
            window._3rbSkinSyncInputHooked = true;
            window._3rbVerbose && console.log('[SkinSync] ✓ Skin input hooked for instant sync');
            return;
        }
        if (tries++ < 100) setTimeout(tryHook, 300);
    };
    tryHook();
})();

// Auto-start skin sync when the WebSocket connects
(function autoStartSkinSync() {
    let started = false;
    const check = () => {
        if (started) return;
        if (window._3rbSlot1Sock && window._3rbSlot1Sock.readyState === 1 && window._3rbSlot1Sock._3rbCaptchaSent) {
            started = true;
            window._3rbStartSkinSync();
        }
    };
    setInterval(check, 2000);
})();

(function hookHsloChat() {
    let tries = 0;
    const tryHook = () => {
        if (window.class_e && typeof window.class_e.message === 'function') {
            const originalMessage = window.class_e.message;
            window.class_e.message = function(op, msg, tab) {
                try {
                    // op 101 represents outgoing normal chat messages from HSLO's input box
                    if (op === 101 && msg) {
                        window._3rbSendGameChat(msg);
                    }
                } catch (err) {
                    window._3rbVerbose && console.error('[hslo-mod] Chat intercept error:', err);
                }
                return originalMessage.apply(this, arguments);
            };
            window._3rbVerbose && console.log('[hslo-mod] ✓ Chat message sending hook installed successfully');
            return;
        }
        if (tries++ < 100) setTimeout(tryHook, 200);
    };
    tryHook();
})();

// ═══════════════════════════════════════════════════════════════
// SKIN FIX: Remove the hardcoded kbfjWV1 default & show real skins
// ═══════════════════════════════════════════════════════════════
(function fixSkins() {
    // The placeholder skin HSLO assigns to every empty profile slot.
    // When no real skin is configured, own cells AND other mod-users' cells
    // all look identical. Fix: clear the placeholder so cells fall back to
    // their server-assigned skin (from 3rb.io's res/skins CDN) or just colour.
    var PLACEHOLDER = 'https://i.imgur.com/kbfjWV1.png';

    // Purge saved placeholder skin & force everyoneSkins setting off
    try {
        var profs = JSON.parse(localStorage.getItem('profiles') || '{}');
        var changed = false;
        Object.keys(profs).forEach(function(k) {
            if (profs[k]) {
                if (profs[k].skin === PLACEHOLDER) { profs[k].skin = ''; changed = true; }
                if (profs[k].skin2 === PLACEHOLDER) { profs[k].skin2 = ''; changed = true; }
            }
        });
        if (changed) localStorage.setItem('profiles', JSON.stringify(profs));

        var st = JSON.parse(localStorage.getItem('settings') || '{}');
        if (st.everyoneSkins !== 'off' || st.autoZoom !== 'off') {
            st.everyoneSkins = 'off';
            st.autoZoom = 'off';
            localStorage.setItem('settings', JSON.stringify(st));
        }
    } catch(e) {}

    // ── 1. Clear own-cell default skin ──────────────────────────
    // Patches window.classb (the profile manager) so new / empty profiles
    // start with an empty skin instead of the placeholder.
    function patchProfileManager() {
        var mgr = window.classb;
        if (!mgr || typeof mgr.switch !== 'function') return false;

        var _origSwitch = mgr.switch.bind(mgr);
        mgr.switch = function(slot) {
            _origSwitch(slot);
            // After HSLO sets the profile, clear the placeholder skin from the inputs.
            var s1 = document.getElementById('skin');
            var s2 = document.getElementById('skin2');
            if (s1 && s1.value === PLACEHOLDER) {
                s1.value = '';
                if (window.classA) window.classA.skin  = '';
            }
            if (s2 && s2.value === PLACEHOLDER) {
                s2.value = '';
                if (window.classA) window.classA.skin2 = '';
            }
        };

        // Trigger immediately for the currently selected profile
        var currentSlot = mgr.selected || 1;
        mgr.switch(currentSlot);
        return true;
    }

    // ── 2. Fix teammate / other-player fallback in skinMap ───────
    // bundle.js falls back to O5k0G4p.png for cells without a server skin.
    // We patch the renderer class so cells with no skin show ONLY their colour.
    function patchRenderer() {
        var renderer = window.classN; // HSLO renderer (holds skinMap & downloadedSkins)
        if (!renderer || !renderer.prototype) return false;

        // Patch buildSkinMap: intercept the teammate-fallback path.
        // We override getCustomSkin so returning false (no skin) is clean.
        var origGetCustomSkin = renderer.prototype.getCustomSkin;
        if (origGetCustomSkin) {
            renderer.prototype.getCustomSkin = function(worldID) {
                var url = this.skinMap ? this.skinMap.get(worldID) : undefined;
                // If the skinMap entry is the O5k0G4p placeholder, treat as no skin.
                if (url === 'https://i.imgur.com/O5k0G4p.png' ||
                    url === 'https://i.imgur.com/kbfjWV1.png') return false;
                return origGetCustomSkin.call(this, worldID);
            };
        }
        return true;
    }

    // ── 3. Per-frame skinMap cleanup ─────────────────────────────
    // Because HSLO rebuilds skinMap every render tick, we also intercept
    // buildSkinMap to remove placeholder entries as soon as they are added.
    function patchBuildSkinMap() {
        var renderer = window.classN;
        if (!renderer || !renderer.prototype) return false;
        var fnName = Object.getOwnPropertyNames(renderer.prototype).find(function(k) {
            // Look for the method that calls skinMap.set
            try { return renderer.prototype[k].toString().indexOf('skinMap.set') !== -1; } catch(e) { return false; }
        });
        if (!fnName) return false;

        var _origBuild = renderer.prototype[fnName];
        renderer.prototype[fnName] = function() {
            _origBuild.apply(this, arguments);
            // Remove placeholder entries so those cells render with just colour
            if (this.skinMap) {
                this.skinMap.forEach(function(url, id, map) {
                    if (url === 'https://i.imgur.com/kbfjWV1.png' ||
                        url === 'https://i.imgur.com/O5k0G4p.png') {
                        map.set(id, ''); // empty → getCustomSkin returns false → colour only
                    }
                });
            }
        };
        return true;
    }

    var tries = 0;
    var patchedProfile  = false;
    var patchedRenderer = false;
    var patchedBuild    = false;

    var t = setInterval(function() {
        if (!patchedProfile)  patchedProfile  = patchProfileManager();
        if (!patchedRenderer) patchedRenderer = patchRenderer();
        if (!patchedBuild)    patchedBuild    = patchBuildSkinMap();

        if (patchedProfile && patchedRenderer && patchedBuild) {
            clearInterval(t);
            console.log('[hslo-mod] ✓ Skin fix applied: placeholder skins removed, cells will show real skins or colour only.');
        }
        if (tries++ > 200) {
            clearInterval(t);
            console.log('[hslo-mod] ⚠ Skin fix: could not patch all methods (game version may differ).');
        }
    }, 200);
})();

// ═══════════════════════════════════════════════════════════════
// HSLO MOD EXTENSIONS: Auto-Respawn Tab 2, Camera Lock, Tab 2 Hotkeys
// ═══════════════════════════════════════════════════════════════
(function initHsloExtensions() {

    // ── 1. Load saved settings ──────────────────────────────────
    window._3rbKeyTab2Split       = localStorage.getItem('_3rbKeyTab2Split')       || 'Z';
    window._3rbKeyTab2Double      = localStorage.getItem('_3rbKeyTab2Double')      || 'X';
    // _3rbKeyTab2Split16 replaces the old _3rbKeyTab2Trick. Fall back to the old saved value for backward-compat.
    window._3rbKeyTab2Split16     = localStorage.getItem('_3rbKeyTab2Split16')     ||
                                     localStorage.getItem('_3rbKeyTab2Trick')       || 'C';
    // Keep _3rbKeyTab2Trick as an alias so any code still reading the old name continues to work.
    window._3rbKeyTab2Trick       = window._3rbKeyTab2Split16;
    window._3rbKeyTab2Respawn     = localStorage.getItem('_3rbKeyTab2Respawn')     || 'V';
    window._3rbKeepLastDirection  = localStorage.getItem('_3rbKeepLastDirection')  === 'true';

    // Restore saved key values into the hotkey input boxes once the DOM is ready
    (function restoreTab2Keys() {
        var tries = 0;
        var t = setInterval(function() {
            var s   = document.getElementById('_3rb-key-tab2-split');
            var d   = document.getElementById('_3rb-key-tab2-double');
            var s16 = document.getElementById('_3rb-key-tab2-split16');
            var rsp = document.getElementById('_3rb-key-tab2-respawn');

            // Restore UI button state for Continuous Background Direction
            var btnOff = document.getElementById('_3rb-toggle-keepdir-off');
            var btnOn  = document.getElementById('_3rb-toggle-keepdir-on');
            if (btnOff && btnOn) {
                btnOff.className = window._3rbKeepLastDirection ? '' : 'active';
                btnOn.className  = window._3rbKeepLastDirection ? 'active' : '';
            }

            if (s && d && s16) {
                clearInterval(t);
                s.value   = window._3rbKeyTab2Split;
                d.value   = window._3rbKeyTab2Double;
                s16.value = window._3rbKeyTab2Split16;
                if (rsp) rsp.value = window._3rbKeyTab2Respawn;
            }
            if (tries++ > 100) clearInterval(t);
        }, 200);
    })();

    // ── 4. Tab 2 Split Functions ─────────────────────────────────

    // ── 4. Tab 2 Split Functions ─────────────────────────────────
    // Normalize a stored key to match ev.code format
    function keyMatches(storedKey, ev) {
        var code = ev.code || '';
        var key  = ev.key  || '';
        var s = (storedKey || '').trim();
        // Exact match (e.g. 'KeyZ')
        if (code === s) return true;
        // Single letter stored as 'Z', code is 'KeyZ'
        if (code === 'Key' + s.toUpperCase()) return true;
        // Match by ev.key
        if (key.toUpperCase() === s.toUpperCase()) return true;
        return false;
    }

    // ── 4. Track which tab is currently being controlled ────────
    // Starts at 1 (Tab 1 controlled). Toggles every time the multibox switch key fires.
    window._3rbControlledTab = 1;

    // Helper: read the multibox-switch key live from the HSLO hotkey input
    function getMultiboxSwitchKey() {
        var el = document.querySelector('[name="multiboxTab"] input.key');
        return el ? el.value.trim() : 'Tab';
    }

    // Listen for the multibox switch key in BUBBLE phase so HSLO handles the actual
    // tab switch first; we just count the toggle.
    document.addEventListener('keydown', function(ev) {
        var tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
        if (tag === 'input' || tag === 'textarea' || tag === 'select') return;
        var mbKey = getMultiboxSwitchKey();
        if (keyMatches(mbKey, ev)) {
            window._3rbControlledTab = (window._3rbControlledTab === 1) ? 2 : 1;
            console.log('[MAD PLUS] Switched control \u2192 Tab', window._3rbControlledTab);
        }
    }, false); // bubble phase — HSLO processes first, then we toggle

    // ── 5. Split the OTHER (background) tab ─────────────────────
    // Always sends the split command to whichever tab is NOT being controlled.
    function splitOtherTab(times) {
        times = times || 1;

        // Decide which slot to split: the one NOT currently controlled
        var otherSlot = (window._3rbControlledTab === 1) ? 2 : 1;
        var ws    = (otherSlot === 2) ? window._3rbSlot2Sock  : window._3rbSlot1Sock;
        var proxy = (otherSlot === 2) ? window._3rbProxySlot2 : window._3rbProxySlot1;

        if (!ws || ws.readyState !== 1) {
            console.warn('[MAD PLUS] splitOtherTab: slot', otherSlot, 'socket not open');
            return;
        }
        if (!ws._3rbCaptchaSent) {
            console.warn('[MAD PLUS] splitOtherTab: slot', otherSlot, 'not authenticated yet');
            return;
        }

        console.log('[MAD PLUS] splitOtherTab x' + times, '(controlled=Tab' + window._3rbControlledTab + ' \u2192 splitting Tab' + otherSlot + ')');

        for (var i = 0; i < times; i++) {
            (function(delay) {
                setTimeout(function() {
                    try {
                        // IMPORTANT: 3rb.io uses a SIG opcode-shuffle table (_3rbQe).
                        // _rawSendV5() applies the shuffle automatically.
                        if (proxy && typeof proxy._rawSendV5 === 'function') {
                            proxy._rawSendV5(new Uint8Array([17]).buffer);
                        } else if (ws._3rbQe) {
                            ws._nativeSend(new Uint8Array([ws._3rbQe[17]]).buffer);
                        } else {
                            ws._nativeSend(new Uint8Array([17]).buffer);
                        }
                    } catch(e) { console.warn('[MAD PLUS] splitOtherTab send error:', e); }
                }, delay);
            })(i * 60);
        }
    }

    // ── 6. Reconnect the OTHER (background) tab ─────────────────
    // Directly triggers q.reconnect(2) when controlling Tab 1, or q.reconnect(1) when controlling Tab 2
    function fastRespawnOtherTab() {
        var otherSlot = (window._3rbControlledTab === 1) ? 2 : 1;
        console.log('[MAD PLUS] 🔄 Reconnecting Tab', otherSlot);

        if (window.classq && typeof window.classq.reconnect === 'function') {
            try {
                window.classq.reconnect(otherSlot);
                return;
            } catch(e) {}
        }

        var btnId = (otherSlot === 2) ? 'reconnect02' : 'reconnect01';
        var btn = document.getElementById(btnId);
        if (btn) btn.click();
    }

    // Keep old name as alias for any external code that might call it
    window._3rbSplitTab2    = splitOtherTab;
    window._3rbSplitOtherTab = splitOtherTab;
    window._3rbFastRespawnOtherTab = fastRespawnOtherTab;

    // ── 7. Keyboard Listener for the Tab 2 hotkeys ───────────────
    // Read key value live from the DOM input (HSLO sets .value programmatically so
    // 'onchange' never fires — reading at event-time is the only reliable approach).
    function readTab2Key(elId, windowVar, storageKey, fallback) {
        var el = document.getElementById(elId);
        var v  = el ? el.value.trim() : '';
        if (v) {
            if (window[windowVar] !== v) {
                window[windowVar] = v;
                localStorage.setItem(storageKey, v);
            }
            return v;
        }
        return window[windowVar] || fallback;
    }

    document.addEventListener('keydown', function(ev) {
        var tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
        if (tag === 'input' || tag === 'textarea' || tag === 'select') return;

        var splitKey     = readTab2Key('_3rb-key-tab2-split',   '_3rbKeyTab2Split',   '_3rbKeyTab2Split',   'Z');
        var doubleKey    = readTab2Key('_3rb-key-tab2-double',  '_3rbKeyTab2Double',  '_3rbKeyTab2Double',  'X');
        var split16Key   = readTab2Key('_3rb-key-tab2-split16', '_3rbKeyTab2Split16', '_3rbKeyTab2Split16', 'C');
        var respawnKey   = readTab2Key('_3rb-key-tab2-respawn', '_3rbKeyTab2Respawn', '_3rbKeyTab2Respawn', 'V');
        var singleCamKey = readTab2Key('_3rb-key-singlecam',    '_3rbKeySingleCam',   '_3rbKeySingleCam',   'J');

        if (keyMatches(splitKey, ev)) {
            ev.stopImmediatePropagation();
            ev.preventDefault();
            splitOtherTab(1); // Split — splits the background tab
        } else if (keyMatches(doubleKey, ev)) {
            ev.stopImmediatePropagation();
            ev.preventDefault();
            splitOtherTab(2); // Double Split
        } else if (keyMatches(split16Key, ev)) {
            ev.stopImmediatePropagation();
            ev.preventDefault();
            splitOtherTab(4); // Split 16
        } else if (keyMatches(respawnKey, ev)) {
            ev.stopImmediatePropagation();
            ev.preventDefault();
            fastRespawnOtherTab(); // Fast Respawn / Kill
        } else if (keyMatches(singleCamKey, ev)) {
            ev.stopImmediatePropagation();
            ev.preventDefault();
            window._3rbFocusSingleCam = !window._3rbFocusSingleCam;
            updateSingleCamUI();
            console.log('[MAD PLUS] 📷 Toggle Focus Single Tab Camera:', window._3rbFocusSingleCam ? 'ON' : 'OFF');
        }
    }, true); // capture=true fires before HSLO's own keydown listeners

    console.log('[hslo-mod] ✓ splitOtherTab ready. Tab2 Keys \u2192 Split:', window._3rbKeyTab2Split, '| Double:', window._3rbKeyTab2Double, '| Split16:', window._3rbKeyTab2Split16);
})();


