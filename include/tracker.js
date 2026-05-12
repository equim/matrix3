import CspReport from '/include/cspreport.js'
import * as psl from '/include/psl.js'

// Imagine a document with an embedded youtube video, the toplevel document
// will script src the youtube embedded script, which creates an iframe that
// contains the video.
// The user might allow this origin to load scripts and frames from youtube
// but that doesn't imply that the frame will have permission to play media.
// This will be confusing behaviour, because the user will have to navigate
// to youtube, apply all the permissions, then reload the broken site.
// Instead, we track subresource violations and populate the report form so
// it can all be done on the same page.

// The information we track about a tab
class Tab {
    server = {};
    policy = {};
}

// This class keeps track of observed violations so we can give the user hints.
export default class ViolationTracker {
    #tabs;

    constructor () {
        this.#tabs = new Map();
    }

    #getOrCreateTab(tabId) {
        if (this.#tabs.has(tabId) == false) {
            this.#tabs.set(tabId, new Tab());
        }
        return this.#tabs.get(tabId);
    }

    async addTabViolation(tabId, report) {
        let tab = this.#getOrCreateTab(tabId);
        let blocked = report.blocked?.origin;
        let origin = report.initiator?.origin;

        if (!report.initiator || !report.blocked)
            return;

        // Normalize some sources
        if (blocked == origin) {
            blocked = "'self'";
        } else if (blocked == "null") {
            blocked = CspReport.protocolSource(report.blocked.protocol);
            if (blocked === undefined)
                console.log("tracker", "what is this", report.blocked);
        } else {
            // Collapse subdomain origins to a wildcard at the user's chosen
            // scope so they aren't drowning in per-host directives. In "host"
            // scope getScopedDomain returns the hostname unchanged and the
            // wildcard branch below becomes a no-op.
            const u = new URL(blocked);
            const scoped = await psl.getScopedDomain(u.hostname);
            let hostpart = scoped;
            if (u.hostname != scoped)
                hostpart = `*.${scoped}`;
            blocked = `${u.protocol}//${hostpart}`;
        }

        // Bucket by the initiator at the user's chosen scope so the panel
        // can find it with the same key it puts in the dropdown.
        let domain = await psl.getScopedDomain(new URL(origin).hostname);

        tab.policy[domain] ??= {};
        tab.policy[domain][report.directive] ??= new Set();
        tab.policy[domain][report.directive].add(blocked);
    }

    // Called when the origin changes, throw away what we know.
    resetTab(tabId) {
        this.#tabs.delete(tabId);
    }

    async addServerPolicy(tabId, url, header) {
        let tab = this.#getOrCreateTab(tabId);
        let domain = await psl.getScopedDomain(new URL(url).hostname);
        tab.server[domain] ??= new Set();
        tab.server[domain].add(header);
    }

    getServerPolicy(tabId, domain) {
        let tab = this.#getOrCreateTab(tabId);
        return Array.from(tab.server[domain] ?? []);
    }

    getDirectives(tabId, domain) {
        let tab = this.#getOrCreateTab(tabId);
        let bucket = tab.policy[domain] ?? {};

        return Object.fromEntries(
            Object.entries(bucket).map(([key, value]) => [key, Array.from(value)])
        );
    }

}

