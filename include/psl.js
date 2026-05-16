// Public Suffix List lookup. The exported API is intentionally minimal so
// the implementation can be swapped without touching callers.
//
import { getDomain } from '/vendor/tldts.js';
import Options from '/include/options.js'

// Returns the registrable domain for `host`, e.g. "mail.google.com" ->
// "google.com". Returns `host` unchanged for IPs, single-label hostnames,
// or unparseable input.
export function getRegistrableDomain(host)
{
    return getDomain(host) ?? host;
}

// Resolves `host` to the scope the user picked in Options. "domain" is the
// PSL registrable; "host" returns the literal hostname.
export async function getScopedDomain(host)
{
    let options = await Options.get();

    switch (options?.defaultscope) {
        case "host":
            return host;
        case "domain":
        default:
            return getRegistrableDomain(host);
    }
}
