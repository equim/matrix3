import CspReport from '/include/cspreport.js'
import ViolationTracker from '/include/tracker.js'
import RequestServer from '/server.js'
import Rules from '/include/rules.js'
import { MessageTypes } from '/include/commands.js'

let tracker = new ViolationTracker();
let server = new RequestServer(tracker);

// Apply stored options on browser-start / install -- otherwise the saved
// defaultpolicy slider doesn't take effect until the sidepanel opens.
async function applyStoredOptions() {
    let { options } = await chrome.storage.sync.get("options");
    let rules;
    if (options?.defaultpolicy === undefined)
        return;
    rules = new Rules();
    await rules.init();
    await rules.applyDefaultPolicy(options.defaultpolicy);
}
chrome.runtime.onStartup.addListener(() => applyStoredOptions());
chrome.runtime.onInstalled.addListener(() => applyStoredOptions());

// Set a badge on the toolbar icon for the given tab. Skipped when the
// `badges` option is off so users can opt out of the visual clutter.
async function setBadge(tabId, text, color) {
    let { options } = await chrome.storage.sync.get("options");
    if (!options?.badges)
        return;
    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });
}

function clearBadge(tabId) {
    chrome.action.setBadgeText({ text: '', tabId });
}

// Track what security policy hosts request, and make it available to users.
chrome.webRequest.onHeadersReceived.addListener(async (details) => {
        let csp = details.responseHeaders.filter(hdr => hdr.name.toLowerCase() == "content-security-policy");

        console.log("hdr", details.tabId, details.documentLifecycle, details.frameType, details.url);

        for (let hdr of csp)
            await tracker.addServerPolicy(details.tabId, details.url, hdr.value);
        if (csp.length)
            chrome.runtime.sendMessage({
                command: MessageTypes.NOTIFY_UPDATE,
                   data: { id: details.tabId }
            }).catch(() => {});
    }, {
        types: [ "main_frame", "sub_frame" ],
        urls: [ "<all_urls>" ]
    }, [ "responseHeaders" ]
);

// Monitor for CSP violation reports.
chrome.webRequest.onBeforeRequest.addListener(async (details) => {
        // Drop reports from documents that no longer exist -- POSTs from the
        // previous page can still be in flight when the user reloads.
        if (!tracker.hasDocument(details.tabId, details.documentId))
            return;
        await tracker.addTabViolation(details.tabId, new CspReport(details));
        setBadge(details.tabId, "!", "#dc2626");
        chrome.runtime.sendMessage({
            command: MessageTypes.NOTIFY_UPDATE,
               data: { id: details.tabId }
        }).catch(() => {});
    }, {
        types: [ "csp_report" ],
         urls: [ "<all_urls>" ]
    }, [ "requestBody" ]
);

// Record each frame's documentId at commit time. resetTab clears them
// alongside everything else, so a top-frame navigation wipes the whole tree.
chrome.webNavigation.onCommitted.addListener((details) => {
    tracker.addDocument(details.tabId, details.documentId);
});

// Make the matrix button open the sidepanel.
chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true }).catch((error) => console.error(error));

// Reset before the request so the CSP captured by onHeadersReceived survives.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0)
        return;
    tracker.resetTab(details.tabId);
    clearBadge(details.tabId);
});
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
    console.log("service", "onremoved", tabId, removeInfo);
    tracker.resetTab(tabId);
});
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
    console.log("service", "onreplaced", addedTabId, removedTabId);
    tracker.resetTab(removedTabId);
});
