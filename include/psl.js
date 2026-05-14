// Public Suffix List lookup. The exported API is intentionally minimal so
// the implementation can be swapped without touching callers.
//
import { getDomain } from '/vendor/tldts.js';

// Returns the registrable domain for `host`, e.g. "mail.google.com" ->
// "google.com". Returns `host` unchanged for IPs, single-label hostnames,
// or unparseable input.
export function getRegistrableDomain(host)
{
    return getDomain(host) ?? host;
}

let optionsCache = null;

const optionsPromise = chrome.storage.sync.get("options").then(({ options }) => {
    optionsCache = options || {};

    chrome.storage.onChanged.addListener((changes) => {
        if (changes.options)
            optionsCache = changes.options.newValue;
    });
});

// Resolves `host` to the scope the user picked in Options. "domain" is the
// PSL registrable; "host" returns the literal hostname.
export async function getScopedDomain(host)
{
    if (optionsCache === null) {
        await optionsPromise;
    }

    switch (optionsCache?.defaultscope) {
        case "host":
            return host;
        case "domain":
        default:
            return getRegistrableDomain(host);
    }
}

// Alternative PSL probe via Chrome's cookies API. Chrome refuses to set a
// cookie whose `domain` is itself a public suffix, so we climb the labels
// right-to-left and return the shortest one Chrome accepted.
// Requires cookie permission.

const cookieCache = new Map();
export async function getRegistrableDomainViaCookies(host)
{
    if (cookieCache.has(host))
        return cookieCache.get(host);

    let url;
    try {
        url = new URL(`https://${host}/`);
    } catch {
        cookieCache.set(host, host);
        return host;
    }

    if (!url.hostname.includes('.')) {
        cookieCache.set(host, host);
        return host;
    }

    const labels = url.hostname.split('.');

    for (let i = 1; i < labels.length; i++) {
        const candidate = labels.slice(-i - 1).join('.');

        if (cookieCache.has(candidate)) {
            const cached = cookieCache.get(candidate);
            cookieCache.set(host, cached);
            return cached;
        }

        const cookie = await chrome.cookies.set({
            url: url.href,
            name: '__matrix3_psl_probe',
            value: '1',
            domain: candidate,
            expirationDate: Date.now() / 1000 + 60
        }).catch(() => null);
        if (cookie) {
            await chrome.cookies.remove({url: url.href, name: '__matrix3_psl_probe'});
            cookieCache.set(candidate, candidate);
            cookieCache.set(host, candidate);
            return candidate;
        }
    }

    cookieCache.set(host, host);
    return host;
}
