// Public Suffix List lookup. The exported API is intentionally minimal so the
// implementation can be swapped (bundled PSL data, tldts, etc.) without
// touching callers.
//
// Current implementation: probe Chrome's built-in PSL via the cookies API.
// Chrome refuses to set a cookie whose `domain` is itself a public suffix, so
// we climb the labels right-to-left and return the shortest one Chrome accepted.
// IP literals fall out naturally — every partial-IP candidate is rejected and
// we return the host unchanged.

const cache = new Map();

// Returns the registrable domain for `host`, e.g. "mail.google.com" -> "google.com".
// Returns `host` unchanged when no answer can be determined (IPs, single labels,
// or unparseable input).
export async function getRegistrableDomain(host)
{
    if (cache.has(host))
        return cache.get(host);

    let url;
    try {
        url = new URL(`https://${host}/`);
    } catch {
        cache.set(host, host);
        return host;
    }

    if (!url.hostname.includes('.')) {
        cache.set(host, host);
        return host;
    }

    const labels = url.hostname.split('.');

    for (let i = 1; i < labels.length; i++) {
        const candidate = labels.slice(-i - 1).join('.');

        if (cache.has(candidate)) {
            const cached = cache.get(candidate);
            cache.set(host, cached);
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
            cache.set(candidate, candidate);
            cache.set(host, candidate);
            return candidate;
        }
    }

    cache.set(host, host);
    return host;
}

// Resolves `host` to the scope the user picked in Options. "domain" is the
// PSL registrable; "host" returns the literal hostname. Future scopes (eTLD+1,
// protocol-prefixed, etc.) get added as switch cases here.
export async function getScopedDomain(host)
{
    const { options } = await chrome.storage.sync.get("options");
    switch (options?.defaultscope) {
        case "host":
            return host;
        case "domain":
        default:
            return getRegistrableDomain(host);
    }
}
