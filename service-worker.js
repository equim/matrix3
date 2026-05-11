import CspReport from '/include/cspreport.js'
import ViolationTracker from '/include/tracker.js'
import RequestServer from '/server.js'

let tracker = new ViolationTracker();
let server = new RequestServer(tracker);

// Track what security policy hosts request, and make it available to users.
chrome.webRequest.onHeadersReceived.addListener((details) => {
        let csp = details.responseHeaders.filter(hdr => hdr.name.toLowerCase() == "content-security-policy");

        if (csp.length == 0)
            return;

        console.log("csp headers for tab", details.tabId, "url", details.url, csp);
        csp.forEach(hdr => tracker.addServerPolicy(details.tabId, details.url, hdr.value));
    }, {
        types: [ "main_frame", "sub_frame" ],
        urls: [ "<all_urls>" ]
    }, [ "responseHeaders" ]
);

// Monitor for CSP violation reports.
chrome.webRequest.onBeforeRequest.addListener((details) => {
        let csp = new CspReport(details);

        //console.log("csp report for", csp.docuri);

        // Now add this to the map of known directives
        tracker.addTabViolation(details.tabId, csp);
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
