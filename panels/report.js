import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import * as psl from '/include/psl.js'
import Policy from '/include/policy.js'
import * as csp from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")
const originList = document.querySelector("select#frames")
const headerList = document.querySelector("textarea#servercsp")

// TODO: after commit/reset the loaded page is still running under the
// previous CSP (headers are set per-response); we should prompt the user
// to reload so the new state takes effect.
document.getElementById('commit').addEventListener("click", async () => {
    await RulesManager.commitSessionRulesForHost(originList.value);
    updateReport();
});
document.getElementById('reset').addEventListener("click", async () => {
    await RulesManager.resetHostRules(originList.value);
    updateReport();
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

originList.addEventListener("change", () => {
    refreshTable(originList.value);
    populateServerPolicy();
});

// 'none' must be alone in a CSP source list (spec). In every column,
// checking 'none' clears every other source; checking anything else clears
// 'none'.
function enforceNoneLeader(target) {
    let cell = target.closest("td");
    let noneRow = utils.findTableRow(directivesTable, "'none'");
    let col;
    let noneBox;
    let group;

    if (!target.checked)
        return;
    if (!cell || !noneRow)
        return;

    col = cell.cellIndex;
    noneBox = noneRow.cells[col].firstChild;
    group = Array.from(directivesTable.tBodies[0].rows, r => r.cells[col].firstChild);

    if (target === noneBox)
        utils.checkboxMutex(group, noneBox);
    else
        noneBox.checked = false;
}

directivesTable.addEventListener("change", (event) => {
    enforceNoneLeader(event.target);
    setCurrentRules(originList.value);
});
sandboxTable.addEventListener("change", (event) => {
    let sbx = document.querySelector("input#sandbox-enabled");

    // When the user disables sandbox, if there's no default-src set, fall
    // back to 'self' -- otherwise the resulting CSP would implicitly allow
    // everything. Only fire on the sandbox-enabled toggle itself, not on
    // allow-* checkbox changes.
    if (event.target === sbx && !sbx.checked) {
        let col = utils.getTableColProps(directivesTable, "id").indexOf("default-src");
        let boxes = Array.from(directivesTable.tBodies[0].rows, r => r.cells[col].firstChild);
        if (!boxes.some(b => b.checked))
            findCheckbox("'self'", "default-src", true).checked = true;
    }
    setCurrentRules(originList.value);
});

function resetSandboxDirectives()
{
    document.querySelectorAll("td input.sandbox").forEach(el => el.checked = false);
}

function resetDirectivesTable()
{
    utils.clearTable(directivesTable);

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
    let row = directivesTable.tBodies[0].insertRow(-1);
    let cols = utils.getTableColProps(directivesTable, "id");
    let title = document.createElement("th");

    title.textContent = source;
    row.appendChild(title);

    for (let col of cols.slice(1)) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = false;
        box.className = "rule";
        cell.appendChild(box);
    }

    return row;
}

function findCheckbox(source, directive, autoAdd)
{
    let cols = utils.getTableColProps(directivesTable, "id");
    let row = utils.findTableRow(directivesTable, source);
    let colNum = cols.indexOf(directive);

    if (!row && autoAdd) {
        console.log("report", `source name ${source} is unknown, adding`);
        row = addSourceCheckboxRow(source);
    }
    if (!row || colNum == -1) {
        console.log("report", `checkbox for ${directive} ${source} does not exist`);
        return null;
    }

    return row.cells[colNum].firstChild;
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
    let rule = RulesManager.getHostRule(hostName);

    if (!rule) {
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
            for (let id of sources) {
                let box = features.find(f => f.id == id);
                box.checked = true;
            }
            continue;
        }

        if (directive == "report-uri" || directive == "base-uri")
            continue;

        let dir = collapseDirective(directive);
        for (let src of sources)
            setSourceCheckboxState(src, dir, true, className);
    }
}

function setCurrentViolations(data)
{
    for (let directive in data) {
        let dir = collapseDirective(directive);
        for (let src of data[directive])
            setSourceCheckboxClass(src, dir, "violation");
    }
}

async function setCurrentRules(hostName)
{
    let srcs = utils.getTableRowProps(directivesTable, "textContent");
    let dirs = utils.getTableColProps(directivesTable, "id");
    let policy = (await RulesManager.getEmptyRule(hostName)).toPolicy();

    // Throwaway the row-title column id
    dirs.shift();

    // Passthrough security-relevant directives the server set that we don't
    // manage in the UI (frame-ancestors, trusted-types, etc.).
    let tab = await sidepanel.getActiveTab();
    let headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id,
            domain: hostName
        }
    });
    for (let header of headers) {
        let serverPolicy = new Policy().fromHeader(header);
        for (let d in serverPolicy.directives) {
            if (!csp.AllowedPassthruDirectives.has(d)) continue;
            if (!policy.directives[d])
                policy.directives[d] = serverPolicy.directives[d];
        }
    }

    // Reset before write -- see NOTES.md "Inherited directives in setCurrentRules".
    delete policy.directives["default-src"];

    for (let dir of dirs) {
        for (let src of srcs) {
            if (!getSourceCheckboxState(src, dir))
                continue;
            policy.directives[dir] ??= [];
            if (policy.directives[dir].includes(src))
                continue;
            if (policy.directives[dir].includes("'none'"))
                continue;
            if (src == "'none'") {
                policy.directives[dir] = ["'none'"];
                continue;
            }
            policy.directives[dir].push(src);
        }
    }

    // Now check for sandbox policies.
    let sbx = document.querySelector("input#sandbox-enabled");
    let features = Array.from(document.querySelectorAll("td input.sandbox.allow:checked"), f => f.id);

    // Reset before write -- see NOTES.md "Inherited directives in setCurrentRules".
    delete policy.directives.sandbox;
    if (sbx.checked)
        policy.directives.sandbox = features;

    // Okay, give them to the Rules Manager
    RulesManager.addSessionRule(hostName, policy);
}

async function populateOriginList(preferredDomain) {
    let tab = await sidepanel.getActiveTab();
    let frames = await chrome.webNavigation.getAllFrames({tabId: tab.id}) ?? [];

    let domains = new Set();
    let topDomain;
    for (let f of frames) {
        let u = new URL(f.url);
        if (u.origin == "null")
            continue;
        let domain = await psl.getScopedDomain(u.hostname);
        domains.add(domain);
        if (f.frameId === 0)
            topDomain = domain;
    }

    // Keep the preferred domain if it's still on the page, otherwise fall
    // back to the top frame's scoped key.
    let target = topDomain;
    if (domains.has(preferredDomain))
        target = preferredDomain;

    originList.replaceChildren();

    for (let domain of domains) {
        let opt = document.createElement("option");
        opt.textContent = domain;
        opt.value = domain;
        opt.selected = target == domain;
        originList.add(opt);
    }
}

async function populateServerPolicy() {
    let tab = await sidepanel.getActiveTab();

    const headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id,
            domain: originList.value
        }
    });

    headerList.value = headers.join("\n") || "none";
}

async function refreshViolations(domain) {
    if (!domain) return;
    let tab = await sidepanel.getActiveTab();

    const violations = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_POLICY,
           data: {
                id: tab.id,
            domain: domain
        }
    });

    setCurrentViolations(violations);
    utils.sortTable(directivesTable);
}

async function refreshTable(domain) {
    if (!domain) return;
    resetDirectivesTable();
    resetSandboxDirectives();
    await getCurrentRules(domain);
    await refreshViolations(domain);
}

async function updateReport() {
    let prev = originList.value;

    await populateOriginList(prev);
    await refreshTable(originList.value);
    populateServerPolicy();
}

chrome.webNavigation.onCommitted.addListener(() => updateReport());
chrome.tabs.onActivated.addListener(() => updateReport());
chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_UPDATE:
            refreshViolations(originList.value);
            populateServerPolicy();
            break;
    }
});

updateReport();
