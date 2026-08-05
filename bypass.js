// bypass.js - TrustedTypes CSP bypass (document_start, world=MAIN, runs before any page script)
// 3rb.io ships a `trusted-types twKxV6 default` CSP directive WITHOUT `allow-duplicates`. Cloudflare's
// web.js then tries to create a `forceInner` policy (not allow-listed) AND a second `default` policy
// → both throw `Uncaught` and can wedge the page. We wrap createPolicy so EVERY disallowed/duplicate
// creation returns a pass-through mock instead of throwing.
(function() {
    if (!window.trustedTypes || !window.trustedTypes.createPolicy) return;

    const mock = (name) => ({
        name: name,
        createHTML: (s) => s,
        createScript: (s) => s,
        createScriptURL: (s) => s
    });

    const original = window.TrustedTypePolicyFactory.prototype.createPolicy;

    // Hook: any createPolicy that throws returns a mock
    const cache = Object.create(null);
    window.TrustedTypePolicyFactory.prototype.createPolicy = function(name, options) {
        if (cache[name]) return cache[name];
        let p;
        if (name === 'forceInner') {
            p = mock(name);
        } else {
            try {
                p = original.call(this, name, options);
            } catch (e) {
                p = mock(name);
            }
        }
        cache[name] = p;
        return p;
    };
})();
