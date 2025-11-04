import * as Utils from '/include/utils.js'
import * as Server from './server.js'
import CspReport from '/include/cspreport.js'
import ViolationTracker from '/include/tracker.js'
import RequestServer from '/server.js'

let tracker = new ViolationTracker();
let server = new RequestServer(tracker);

// Track what security policy hosts request, and make it available to users.
chrome.webRequest.onHeadersReceived.addListener((details) => {
        let csp = details.responseHeaders.filter(hdr => hdr.name == "content-security-policy");

        if (csp.length == 0)
            return;

        console.log("csp headers for tab", details.tabId, "url", details.url, csp);
        csp.forEach(hdr => tracker.addServerPolicy(details.tabId, hdr.value));
        return;
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
        return;
    }, {
        types: [ "csp_report" ],
         urls: [ "<all_urls>" ]
    }, [ "requestBody" ]
);

// Make the matrix button open the sidepanel.
chrome.sidePanel.setPanelBehavior({openPanelOnActionClick: true }).catch((error) => console.error(error));

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    //console.log("service", "onupdated", tabId, changeInfo, tab);
    tracker.setTabUpdated(tabId, tab);
});
chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
    console.log("service", "onremoved", tabId, removeInfo);
    tracker.resetTab(tabId);
});
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
    console.log("service", "onreplaced", addedTabId, removedTabId);
    tracker.resetTab(removedTabId);
});
