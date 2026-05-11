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
    server = new Set();
    policy = {};
    origin;
    id;
    status;

    constructor(tabId) {
        this.id = tabId;
    }
}

// This class keeps track of observed violations so we can give the user hints.
export default class ViolationTracker {
    #tabs;

    constructor () {
        this.#tabs = new Map();
    }

    #getOrCreateTab(tabId) {
        if (this.#tabs.has(tabId) == false) {
            this.#tabs.set(tabId, new Tab(tabId));
        }
        return this.#tabs.get(tabId);
    }

    async addTabViolation(tabId, report) {
        let tab = this.#getOrCreateTab(tabId);
        let blocked = report.blocked?.origin;
        let origin = report.initiator?.origin;

        // Normalize some sources
        if (blocked == origin) {
            blocked = "'self'";
        } else if (blocked == "null") {
            switch (report.blocked.protocol) {
                case "unsafe-inline:":
                case "inline:":
                    blocked = "'unsafe-inline'";
                    break;
                case "wasm-eval:":
                    blocked = "'wasm-unsafe-eval'";
                    break;
                case "eval:":
                    blocked = "'unsafe-eval'";
                    break;
                case "about:":
                case "data:":
                case "blob:":
                        blocked = report.blocked.protocol;
                        break;
                default:
                    console.log("tracker", "what is this", report.blocked);
            }
        } else {
            // Collapse subdomain origins to a registrable-domain wildcard so
            // the user isn't drowning in per-host directives.
            const u = new URL(blocked);
            const registrable = await psl.getRegistrableDomain(u.hostname);
            let hostpart = registrable;
            if (u.hostname != registrable)
                hostpart = `*.${registrable}`;
            blocked = `${u.protocol}//${hostpart}`;
        }

        // Bucket by the initiator's registrable domain so the panel can find
        // it with the same key it puts in the dropdown.
        let domain = await psl.getRegistrableDomain(new URL(origin).hostname);

        if (!Object.hasOwn(tab.policy, domain))
            tab.policy[domain] = {};
        if (!Object.hasOwn(tab.policy[domain], report.directive))
            tab.policy[domain][report.directive] = new Set();

        tab.policy[domain][report.directive].add(blocked);
    }

    // Called when the origin changes, throw away what we know.
    resetTab(tabId) {
        this.#tabs.delete(tabId);
    }

    addServerPolicy(tabId, header) {
        let tab = this.#getOrCreateTab(tabId);
        tab.server.add(header);
    }

    getServerPolicy(tabId) {
        return Array.from(this.#getOrCreateTab(tabId).server);
    }

    getDirectives(tabId, domain) {
        let tab = this.#getOrCreateTab(tabId);
        let bucket = tab.policy[domain] ?? {};

        return Object.fromEntries(
            Object.entries(bucket).map(([key, value]) => [key, Array.from(value)])
        );
    }

    // Called from chrome.tabs.onUpdated for every tab change (status, url, title, etc).
    // Records the tab's current status and origin, and discards any accumulated
    // policy/origin data when the top-frame origin changes (cross-origin navigation).
    setTabUpdated(tabId, target) {
        let tab = this.#tabs.get(tabId);
        let url = new URL(target.url);

        if (tab?.origin != url.origin)
            this.resetTab(tabId);

        tab = this.#getOrCreateTab(tabId);
        tab.status = target.status;
        tab.origin = url.origin;
    }
}

