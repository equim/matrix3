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
