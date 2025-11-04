import CspReport from '/include/cspreport.js'

// Imagine a document with an embedded youtube video, the toplevel document
// will script src the youtube embedded script, which creates an iframe that
// contains the video.
// The user might allow this origin to load scripts and frames from youtube
// but that doesn't imply that the frame will have permission to play media.
// This will be confusing behaviour, because the user will have to navigate
// to youtube, apply all the permissions, then reload the broken site.
// Instead, we track subresource violations and populate the report form so
// it can all be done on the same page.

class Origin {
    server;     // Any server recommended CSP.
    origin;     // URL() containing origin
    policy;     // Set of observed CSP directives for this origin.
    frameid;    // -1 for outermost, otherwise unique id.
}

// The information we track about a tab
class Tab {
    policy;
    server;
    origin;
    origins;
    id;
    status;

    constructor(tabId) {
        this.server = new Set();
        this.policy = {};
        this.origins = new Map();
        this.id = tabId;
    }

    getOrigin(url) {
        if (this.origins.has(url) == false) {
            this.origins.set(url, new Origin(url))
        }
        return this.origins.get(url);
    }

    getOriginList() {
        return Array.from(this.origins.keys())
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

    getOriginList(tabId) {
        return this.#getOrCreateTab(tabId).getOriginList();
    }

    getServerHeadersList(tabId) {
        return this.#getOrCreateTab(tabId).getOriginList();
    }

    addTabViolation(tabId, report) {
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
                    blocked = "'inline'";
                    break;
                case "wasm-eval:":
                    blocked = "'wasm-eval'";
                    break;
                case "eval:":
                    blocked = "'eval'";
                    break;
                case "about:":
                case "data:":
                case "blob:":
                        blocked = report.blocked.protocol;
                        break;
                default:
                    console.log("tracker", "what is this", report.blocked);
            }
        }

        // Just populate for now to test
        tab.getOrigin(origin);

        // Check if we already know this directive
        if (!Object.hasOwn(tab.policy, report.directive))
            tab.policy[report.directive] = new Set();

        // Add this source to the directive
        tab.policy[report.directive].add(blocked);

        // Record last known origin
        if (report.isOutermost())
            tab.origin = origin;
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

    getDirectives(tabId) {
        let tab = this.#getOrCreateTab(tabId);

        return Object.fromEntries(
            Object.entries(tab.policy).map(([key, value]) => [key, Array.from(value)])
        );
    }

    getOrigins(tabId) {
        let tab = this.#getOrCreateTab(tabId);
        return tab.getOriginList();
    }

    setTabUpdated(tabId, target) {
        let tab = this.#getOrCreateTab(tabId);
        let url = new URL(target.url);

        // Track last known status
        tab.status = target.status;

        // Check if the origin matches
        if (tab.origin != url.origin)
            this.resetTab(tabId);
    }
}

