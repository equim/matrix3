import CspReport from '/include/cspreport.js'
import ViolationTracker from '/include/tracker.js'
import RequestServer from '/server.js'
import Rules from '/include/rules.js'
import { MessageTypes } from '/include/commands.js'

let tracker = new ViolationTracker();
let server = new RequestServer(tracker);

// Apply stored options at browser-start / install. Until this runs the
// manifest defaults are in effect, which doesn't match the user's saved
// defaultpolicy slider -- fixes the "options only apply after opening the
// sidepanel" gap.
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

// Track what security policy hosts request, and make it available to users.
chrome.webRequest.onHeadersReceived.addListener(async (details) => {
        let csp = details.responseHeaders.filter(hdr => hdr.name.toLowerCase() == "content-security-policy");

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
        await tracker.addTabViolation(details.tabId, new CspReport(details));
        chrome.runtime.sendMessage({
            command: MessageTypes.NOTIFY_UPDATE,
               data: { id: details.tabId }
        }).catch(() => {});
    }, {
        types: [ "csp_report" ],
         urls: [ "<all_urls>" ]
    }, [ "requestBody" ]
);

// Make the matrix button open the sidepanel.
chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true }).catch((error) => console.error(error));

// Reset before the request so the CSP captured by onHeadersReceived survives.
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0)
        tracker.resetTab(details.tabId);
});
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
    console.log("service", "onremoved", tabId, removeInfo);
    tracker.resetTab(tabId);
});
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
    console.log("service", "onreplaced", addedTabId, removedTabId);
    tracker.resetTab(removedTabId);
});
