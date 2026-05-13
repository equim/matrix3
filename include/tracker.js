import CspReport from '/include/cspreport.js'
import * as psl from '/include/psl.js'

// Track sub-resource violations and surface them in the report panel, so
// the user can grant per-host permissions without navigating to each blocked
// origin and editing them one at a time.

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
            // Collapse subdomains to a wildcard at the user's chosen scope. In
            // "host" scope getScopedDomain is a passthrough and the wildcard
            // branch below is a no-op.
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

    // Called from webNavigation.onBeforeNavigate; drop everything we know about the tab.
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

