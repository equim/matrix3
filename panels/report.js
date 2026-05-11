import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")
const originList = document.querySelector("select#frames")
const headerList = document.querySelector("textarea#servercsp")

document.getElementById('query').addEventListener("click", () => updateReport());

document.getElementById('apply').addEventListener("click", async () => {
    await setCurrentRules(new URL(originList.value).host);
});
document.getElementById('commit').addEventListener("click", async () => {
    await RulesManager.commitSessionRulesForHost(new URL(originList.value).host);
});
document.getElementById('reset').addEventListener("click", async () => {
    await RulesManager.resetHostRules(new URL(originList.value).host);
});
document.getElementById('reload').addEventListener("click", async () => {
    await chrome.tabs.reload();
});
document.getElementById('togglesbx').addEventListener("click", async () => {
    let style = sandboxTable.computedStyleMap();
    if (style.get("display") == "none") {
        sandboxTable.style.display = "table"
    } else {
        sandboxTable.style.display = "none"
    }
});

originList.addEventListener("change", e => refreshTable(e.target.value));

function resetSandboxDirectives()
{
    let features = Array.from(document.querySelectorAll("td input.sandbox"));
    features.forEach(el => el.checked = false);
}

function resetDirectivesTable()
{
    utils.clearTable(directivesTable, true);

    // Add some default sources.
    addSourceCheckboxRow("'none'");
    addSourceCheckboxRow("'self'");
    addSourceCheckboxRow("'unsafe-eval'");
    addSourceCheckboxRow("'unsafe-inline'");
    addSourceCheckboxRow("https:");
    addSourceCheckboxRow("http:");
    addSourceCheckboxRow("data:");
    addSourceCheckboxRow("blob:");

}

// Add a row with specified source name
function addSourceCheckboxRow(source)
{
    let row = directivesTable.insertRow(-1);
    let num = directivesTable.rows[0].cells.length;
    let title = document.createElement("th");

    title.textContent = source;
    row.appendChild(title);

    for (let i = 1; i < num; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = false;
        box.className = "rule";
        cell.appendChild(box);
    }

    return directivesTable.rows.length - 1;
}

function findCheckbox(source, directive, autoAdd)
{
    let rows = Array.from(directivesTable.rows).map(r => r.cells[0].textContent);
    let cols = Array.from(directivesTable.rows[0].cells).map(c => c.id);
    let rowNum = rows.indexOf(source);
    let colNum = cols.indexOf(directive);

    if (rowNum == -1 && autoAdd) {
        console.log("report", `source name ${source} is unknown, adding`);
        rowNum = addSourceCheckboxRow(source);
    }
    if (rowNum == -1 || colNum == -1) {
        console.log("report", `checkbox for ${directive} ${source} does not exist`);
        return null;
    }

    return directivesTable.rows[rowNum].cells[colNum].firstChild;
}

function setSourceCheckboxState(source, directive, state, className)
{
    let box = findCheckbox(source, directive, true);
    if (!box) return;
    box.checked = state;
    if (className)
        box.classList.add(className);
}

function setSourceCheckboxClass(source, directive, className)
{
    let box = findCheckbox(source, directive, true);
    if (box)
        box.classList.add(className);
}

function getSourceCheckboxState(source, directive)
{
    return findCheckbox(source, directive, false)?.checked;
}

function collapseDirective(directive)
{
    switch (directive) {
        case "script-src-elem":
        case "script-src-attr":
            return "script-src";
        case "style-src-elem":
        case "style-src-attr":
            return "style-src";
    }
    return directive;
}

async function getCurrentRules(hostName)
{
    // Fill in checkboxes based on current rules
    await RulesManager.init();

    let rule = RulesManager.getHostRule(hostName);

    if (typeof rule == "undefined") {
        console.log("report", `no existing rule for ${hostName}`);
        rule = await RulesManager.getEmptyRule(hostName);
    }

    let policy = rule.policy;
    let className = rule.isSession
                  ? "session"
                  : "dynamic";

    for (let directive in policy.directives) {
        let sources = policy.directives[directive];

        if (directive == "sandbox") {
            let sbx = document.querySelector("input#sandbox-enabled");
            let features = Array.from(document.querySelectorAll("td input.sandbox"));

            sbx.checked = true;
            for (let i = 0; i < sources.length; i++) {
                let box = features.find(f => f.id == sources[i]);
                box.checked = true;
            }
            continue;
        }

        if (directive == "report-uri" || directive == "base-uri")
            continue;

        let dir = collapseDirective(directive);
        for (let i = 0; i < sources.length; i++) {
            setSourceCheckboxState(sources[i], dir, true, className);
        }
    }
}

function setCurrentViolations(data)
{
    for (let directive in data) {
        let dir = collapseDirective(directive);
        for (let i = 0; i < data[directive].length; i++) {
            setSourceCheckboxClass(data[directive][i], dir, "violation");
        }
    }
}

async function setCurrentRules(hostName)
{
    let srcs = Array.from(directivesTable.rows).map(r => r.cells[0].textContent);
    let dirs = Array.from(directivesTable.rows[0].cells).map(c => c.id);

    await RulesManager.init();

    let policy = (await RulesManager.getEmptyRule(hostName)).toPolicy();

    // Throwaway the headers
    srcs.shift();
    dirs.shift();

    for (let i = 0; i < dirs.length; i++) {
        for (let j = 0; j < srcs.length; j++) {
            if (!getSourceCheckboxState(srcs[j], dirs[i]))
                continue;
            if (typeof policy.directives[dirs[i]] == "undefined")
                policy.directives[dirs[i]] = [];
            if (policy.directives[dirs[i]].indexOf(srcs[j]) >= 0)
                continue;
            if (policy.directives[dirs[i]].indexOf("'none'") >= 0)
                continue;
            if (srcs[j] == "'none'") {
                policy.directives[dirs[i]] = ["'none'"];
                continue;
            }
            policy.directives[dirs[i]].push(srcs[j]);
        }
    }

    // Now check for sandbox policies.
    let sbx = document.querySelector("input#sandbox-enabled");
    let features = Array.from(document.querySelectorAll("td input.sandbox.allow:checked")).map(f => f.id);

    if (sbx.checked)
        policy.directives.sandbox = features;

    // Okay, give them to the Rules Manager
    RulesManager.addSessionRule(hostName, policy);
}

async function populateOriginList(preferredOrigin) {
    let url = await sidepanel.getActiveUrl();
    let tab = await sidepanel.getActiveTab();
    let frames = await chrome.webNavigation.getAllFrames({tabId: tab.id}) ?? [];

    let origins = new Set();
    for (let f of frames) {
        let origin = new URL(f.url).origin;
        if (origin != "null")
            origins.add(origin);
    }

    // Keep the preferred origin if it's still on the page, otherwise fall
    // back to the top frame (e.g. cross-origin navigation discarded it).
    let target = url.origin;
    if (origins.has(preferredOrigin))
        target = preferredOrigin;

    originList.replaceChildren();

    for (let origin of origins) {
        let opt = document.createElement("option");
        opt.textContent = origin;
        opt.value = origin;
        opt.selected = target == origin;
        originList.add(opt);
    }
}

async function populateServerPolicy() {
    let tab = await sidepanel.getActiveTab();

    // Request a list of known origins.
    const headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id
        }
    });

    headerList.value = headers.join("\n") || "none";
}

async function refreshTable(origin) {
    if (!origin) return;
    let tab = await sidepanel.getActiveTab();
    let host = new URL(origin).host;

    resetDirectivesTable();
    resetSandboxDirectives();

    await getCurrentRules(host);

    const violations = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_POLICY,
           data: {
                id: tab.id,
            origin: origin
        }
    });

    setCurrentViolations(violations);
}

async function updateReport() {
    let prev = originList.value;

    await populateOriginList(prev);
    await refreshTable(originList.value);
    populateServerPolicy();
};

chrome.tabs.onUpdated.addListener(() => updateReport());
chrome.tabs.onActivated.addListener(() => updateReport());

updateReport();
