import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import * as psl from '/include/psl.js'
import Options from '/include/options.js'
import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;
let options = await Options.get();

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")
const originList = document.querySelector("select#frames")
const headerList = document.querySelector("textarea#servercsp")

let currentServerPolicies = [];

// User's last manual origin selection. Sticks across reloads even if a partial
// frame list temporarily falls back to the top domain; cleared on tab switch.
let userOrigin;

// Recognises the prefix of a CSP nonce-source or hash-source value.
const kNonceOrHashPrefix = /^'(?:nonce-|sha(?:256|384|512)-)/;

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
document.getElementById('abandon').addEventListener("click", async () => {
    await RulesManager.abandonSessionRulesForHost(originList.value);
    updateReport();
});
document.getElementById('uncommit').addEventListener("click", async () => {
    await RulesManager.uncommitDynamicRulesForHost(originList.value);
    updateReport();
});
document.getElementById('unblock').addEventListener("click", () => unblockReportedViolations());
document.getElementById('accept').addEventListener("click", () => {
    utils.setCheckboxes(directivesTable.querySelectorAll("td input[type=checkbox]"), false);
    resetSandboxDirectives();
    applyServerPolicy();
});
document.getElementById('merge').addEventListener("click", () => applyServerPolicy());

// Transform a server-supplied source for import. Returns null to skip.
function importableSource(src) {
    if (!src)
        return null;
    if (kNonceOrHashPrefix.test(src))
        return null;
    if (src === "'report-sample'")
        return null;
    if (src === "'strict-dynamic'")
        return "'unsafe-inline'";
    return src;
}

function applyServerSources() {
    let columns = utils.getTableColProps(directivesTable, "id");

    for (let policy of currentServerPolicies) {
        for (let directive in policy.directives) {
            let dir = collapseDirective(directive);

            if (!columns.includes(dir))
                continue;

            for (let src of policy.directives[directive])
                setSourceCheckboxState(importableSource(src), dir, true);
        }
    }

    utils.sortTable(directivesTable, compareSourceRows);
}

function applyServerPolicy() {
    applyServerSources();
    applyServerSandbox();
    setCurrentRules(originList.value);
}

function applyServerSandbox() {
    let sbx = document.querySelector("input#sandbox-enabled");

    for (let policy of currentServerPolicies) {
        let features = policy.directives.sandbox;
        if (!features)
            continue;
        sbx.checked = true;
        for (let id of features) {
            let box = document.getElementById(id);
            if (box?.classList.contains("allow"))
                box.checked = true;
        }
    }
}

function unblockReportedViolations() {
    let boxes = directivesTable.querySelectorAll("input.violation");

    for (let box of boxes)
        box.checked = true;

    setCurrentRules(originList.value);
}
// Apply (or remove) the selected group's origins to default-src, script-src,
// style-src, and img-src. default-src covers other directives via inheritance;
// the rest are commonly set explicitly in strict policies so they need their
// own entries.
function applyTrustGroup(checked) {
    let name = document.getElementById('trustgroup').value;
    let dirs = ["default-src", "script-src", "style-src", "img-src"];
    let origins;

    if (!name)
        return;

    origins = options.groups?.[name] ?? [];

    for (let origin of origins) {
        for (let dir of dirs) {
            let box = findCheckbox(origin, dir, checked);
            if (!box)
                continue;
            box.checked = checked;
            enforceNoneLeader(box);
        }
    }

    if (!checked)
        fallbackToNone();

    utils.sortTable(directivesTable, compareSourceRows);
    setCurrentRules(originList.value);
}

document.getElementById('trust').addEventListener("click", () => applyTrustGroup(true));
document.getElementById('untrust').addEventListener("click", () => applyTrustGroup(false));

originList.addEventListener("change", () => {
    userOrigin = originList.value;
    refreshTable(originList.value);
    populateServerPolicy();
    updateOriginScopeState();
});

// 'none' must be alone in a CSP source list: checking 'none' clears the
// column, checking anything else clears 'none'.
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
    if (event.target.id === "sandbox-enabled")
        fallbackToNone();
    setCurrentRules(originList.value);
});

function resetSandboxDirectives()
{
    utils.setCheckboxes(document.querySelectorAll("td input.sandbox"), false);
}

function resetDirectivesTable()
{
    utils.clearTable(directivesTable);

    // Add some default sources.
    addSourceCheckboxRow("'none'");
    addSourceCheckboxRow("'self'");
    addSourceCheckboxRow("'strict-dynamic'");
    addSourceCheckboxRow("'unsafe-eval'");
    addSourceCheckboxRow("'wasm-unsafe-eval'");
    addSourceCheckboxRow("'unsafe-inline'");
    addSourceCheckboxRow("'unsafe-hashes'");
    addSourceCheckboxRow("https:");
    addSourceCheckboxRow("http:");
    addSourceCheckboxRow("data:");
    addSourceCheckboxRow("blob:");

}

// Add a row with the given source name, or return the existing row.
// Idempotent so callers can blindly re-add the same nonce/hash every refresh.
function addSourceCheckboxRow(source)
{
    let existing = utils.findTableRow(directivesTable, source);
    let cols = utils.getTableColProps(directivesTable, "id");
    let colNodes = directivesTable.querySelectorAll("colgroup col");
    let ignored = options.groups?.Ignore ?? [];
    let row;
    let title;

    if (existing)
        return existing;
    if (ignored.includes(source))
        return null;

    row = directivesTable.tBodies[0].insertRow(-1);
    title = document.createElement("th");

    title.textContent = source;
    title.title = source;
    row.appendChild(title);

    for (let i = 1; i < cols.length; i++) {
        let cell = row.insertCell(-1);
        let box = document.createElement("input");
        box.type = "checkbox";
        box.checked = false;
        box.className = "rule";
        if (colNodes[i].classList.contains("advanced"))
            cell.classList.add("advanced");
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
        console.debug("report", `source name ${source} is unknown, adding`);
        row = addSourceCheckboxRow(source);
    }
    if (!row || colNum == -1) {
        // This could be something we just passthru
        if (!Policy.isAllowedPassthruDirective(directive, options?.defaultscope)) {
            // Nope, might be report-to or similar (safe to ignore).
            console.debug("report", `checkbox for ${directive} ${source} does not exist`);
        }
        return null;
    }

    return row.cells[colNum].firstChild;
}

function setSourceCheckboxState(source, directive, state, className)
{
    if (!source)
        return;
    let box = findCheckbox(source, directive, true);
    if (!box)
        return;
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

// Check 'none' in default-src if nothing else is, so the CSP isn't
// implicitly wide-open. Skipped when sandbox is enabled (sandbox is enough).
function fallbackToNone() {
    let col;
    let boxes;

    if (document.querySelector("input#sandbox-enabled").checked)
        return;

    col = utils.getTableColProps(directivesTable, "id").indexOf("default-src");
    boxes = Array.from(directivesTable.tBodies[0].rows, r => r.cells[col].firstChild);
    if (!boxes.some(b => b.checked))
        findCheckbox("'self'", "default-src", true).checked = true;
}

// Sort sources alphabetically, but with nonce-* / sha*-* values at the end
// since they're noisy and rarely toggled.
function compareSourceRows(a, b) {
    let isHash = l => kNonceOrHashPrefix.test(l);
    let al = a.cells[0].textContent;
    let bl = b.cells[0].textContent;
    return (isHash(al) - isHash(bl)) || al.localeCompare(bl);
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
    let rule = RulesManager.getHostRule(hostName);
    let className;

    if (rule?.isSession)
        className = "session";
    else if (rule)
        className = "dynamic";
    else
        rule = await RulesManager.getEmptyRule(hostName);

    let policy = rule.policy;

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

    // Drop the row-title column id.
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
    let scope = options?.defaultscope;

    for (let header of headers) {
        let serverPolicy = new Policy().fromHeader(header);
        for (let d in serverPolicy.directives) {
            if (!Policy.isAllowedPassthruDirective(d, scope)) {
                console.log("report", `dropped directive ${d} for ${hostName}, not allowed in scope`);
                continue;
            }
            if (policy.directives[d]) {
                console.log("report", `duplicate directive ${d} dropped for ${hostName}`);
                continue;
            }
            policy.directives[d] = serverPolicy.directives[d];
        }
    }

    // Reset before write.
    for (let dir of dirs)
        delete policy.directives[dir];

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

    // Sandbox policies.
    let sbx = document.querySelector("input#sandbox-enabled");
    let features = Array.from(document.querySelectorAll("td input.sandbox.allow:checked"), f => f.id);

    // Reset before write -- see NOTES.md "Inherited directives in setCurrentRules".
    delete policy.directives.sandbox;
    if (sbx.checked)
        policy.directives.sandbox = features;

    await RulesManager.addSessionRule(hostName, policy);
    updateButtonStates();
}

async function populateOriginList(preferredDomain) {
    let tab = await sidepanel.getActiveTab();
    let frames = await chrome.webNavigation.getAllFrames({tabId: tab.id}) ?? [];

    let domains = new Map();
    let topDomain;
    for (let f of frames) {
        let u = new URL(f.url);
        if (u.origin == "null")
            continue;
        let domain = await psl.getScopedDomain(u.hostname);
        if (!domains.has(domain))
            domains.set(domain, u.protocol);
        if (f.frameId === 0)
            topDomain = domain;
    }

    // Keep the preferred domain if it's still on the page, otherwise fall
    // back to the top frame's scoped key.
    let target = topDomain;
    if (domains.has(preferredDomain))
        target = preferredDomain;

    originList.replaceChildren();

    for (let [domain, protocol] of domains) {
        let opt = document.createElement("option");
        opt.textContent = domain;
        opt.value = domain;
        opt.dataset.protocol = protocol;
        opt.selected = target == domain;
        originList.add(opt);
    }
}

async function populateServerPolicy() {
    let tab = await sidepanel.getActiveTab();
    let headers;
    let sources = new Set();

    headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id,
            domain: originList.value
        }
    });

    headerList.value = headers.join("\n") || "none";

    currentServerPolicies = headers.map(h => new Policy().fromHeader(h));

    document.getElementById('accept').disabled = headers.length === 0;
    document.getElementById('merge').disabled = headers.length === 0;

    // Surface per-page nonce-* / hash-* sources from the server CSP so the
    // user can toggle them. Regex matches the CSP3 grammar exactly so we
    // reject anything with garbage characters.
    for (let policy of currentServerPolicies) {
        for (let dir in policy.directives) {
            for (let src of policy.directives[dir]) {
                if (/^'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_-]+={0,2}'$/.test(src))
                    sources.add(src);
            }
        }
    }
    for (let src of sources)
        addSourceCheckboxRow(src);

    utils.sortTable(directivesTable, compareSourceRows);
}

async function refreshViolations(domain) {
    let tab = await sidepanel.getActiveTab();

    if (!domain || !tab) {
        // This can happen with multiple windows or devtools.
        console.debug("report", "refresh requested with unknown domain or tab", domain, tab);
        return;
    }

    const violations = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_POLICY,
           data: {
                id: tab.id,
            domain: domain
        }
    });

    setCurrentViolations(violations);
    utils.sortTable(directivesTable, compareSourceRows);
    updateButtonStates();
}

// Allowlist http(s) only; everything else (chrome:, about:, devtools:, etc.)
// can't be reached by declarativeNetRequest so the controls would lie.
function updateOriginScopeState() {
    let opt = originList.selectedOptions[0];
    let proto = opt?.dataset.protocol;

    document.body.classList.remove("inert");

    if (proto !== "http:" && proto !== "https:") {
        console.debug("report", `unhandled protocol ${proto}, disabling form`);
        document.body.classList.add("inert");
    }
}

// Commit and Abandon only make sense when there's a session rule for the
// host -- otherwise there's nothing to promote or discard. Uncommit is the
// inverse: a dynamic rule with no session draft in the way.
function updateButtonStates() {
    let host = originList.value;
    let rules = RulesManager.getRules().filter(r => r.host === host);
    let hasSession = rules.some(r => r.isSession);
    let hasDynamic = rules.some(r => !r.isSession);
    let hasViolations = directivesTable.querySelector("input.violation") !== null;
    document.getElementById('commit').disabled = !hasSession;
    document.getElementById('abandon').disabled = !hasSession;
    document.getElementById('uncommit').disabled = !hasDynamic || hasSession;
    document.getElementById('unblock').disabled = !hasViolations;
    document.getElementById('reset').disabled = !hasSession && !hasDynamic;
}

async function refreshTable(domain) {
    resetDirectivesTable();
    resetSandboxDirectives();
    await getCurrentRules(domain);
    await refreshViolations(domain);
    updateButtonStates();
}

function populateTrustGroups() {
    let select = document.getElementById('trustgroup');
    let names = Object.keys(options.groups ?? {});

    select.replaceChildren();

    for (let name of names) {
        let opt = document.createElement('option');
        opt.textContent = name;
        opt.value = name;
        select.add(opt);
    }
}

async function updateReport() {
    await populateOriginList(userOrigin ?? originList.value);
    await refreshTable(originList.value);
    populateServerPolicy();
    updateOriginScopeState();
}

chrome.webNavigation.onCommitted.addListener(async (details) => {
    let tab = await sidepanel.getActiveTab();
    if (details.tabId !== tab?.id)
        return;
    updateReport();
});
chrome.tabs.onActivated.addListener((activeInfo) => {
    if (activeInfo.windowId !== sidepanel.current.id)
        return;
    userOrigin = undefined;
    updateReport();
});
async function handleNotifyUpdate(msg) {
    // Ignore updates for tabs we aren't viewing -- when many tabs load
    // concurrently the cross-tab churn would flicker the panel.
    let tab = await sidepanel.getActiveTab();
    if (msg.data?.id !== tab?.id)
        return;
    refreshViolations(originList.value);
    populateServerPolicy();
}

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_UPDATE:
            handleNotifyUpdate(msg);
            break;
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(() => refreshTable(originList.value));
            break;
    }
});

populateTrustGroups();
updateReport();
