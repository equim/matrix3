import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const directivesTable = document.querySelector("table#sources")
const sandboxTable = document.querySelector("table#sandbox")
const originList = document.querySelector("select#frames")
const headerList = document.querySelector("textarea#servercsp")

document.getElementById('query').addEventListener("click", async () => {
    updateReport();
});

document.getElementById('apply').addEventListener("click", async () => {
    let url = await sidepanel.getActiveUrl();
    await setCurrentRules(url.host);
});
document.getElementById('disable').addEventListener("click", async () => {
    // remove sandbox and default-src?
    alert("fixme");
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
    addSourceCheckboxRow("'inline'");
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

function setSourceCheckboxState(source, directive, state, className)
{
    let rows = Array.from(directivesTable.rows).map(r => r.cells[0].textContent);
    let cols = Array.from(directivesTable.rows[0].cells).map(c => c.id);
    let rowNum = rows.indexOf(source);
    let colNum = cols.indexOf(directive);
    let box;

    if (rowNum == -1) {
        console.log("report", `source name ${source} is unknown, adding`);
        rowNum = addSourceCheckboxRow(source);
    }
    if (rowNum == -1 || colNum == -1) {
        console.log("report", `checkbox for ${directive} ${source} does not exist`);
        return;
    }

    box = directivesTable.rows[rowNum].cells[colNum].firstChild;

    box.checked = state;

    if (typeof className != "undefined") {
        box.classList.add(className);
    }
}

function setSourceCheckboxClass(source, directive, className)
{
    let rows = Array.from(directivesTable.rows).map(r => r.cells[0].textContent);
    let cols = Array.from(directivesTable.rows[0].cells).map(c => c.id);
    let rowNum = rows.indexOf(source);
    let colNum = cols.indexOf(directive);
    let box;

    if (rowNum == -1) {
        console.log("report", `source name ${source} is unknown, adding`);
        rowNum = addSourceCheckboxRow(source);
    }
    if (rowNum == -1 || colNum == -1) {
        console.log("report", `checkbox for ${directive} ${source} does not exist`);
        return;
    }

    box = directivesTable.rows[rowNum].cells[colNum].firstChild;
    box.classList.add(className);
}

function getSourceCheckboxState(source, directive)
{
    let rows = Array.from(directivesTable.rows).map(r => r.cells[0].textContent);
    let cols = Array.from(directivesTable.rows[0].cells).map(c => c.id);
    let rowNum = rows.indexOf(source);
    let colNum = cols.indexOf(directive);
    let box;

    if (rowNum == -1 || colNum == -1) {
        console.log("report", `checkbox for ${directive} ${source} does not exist`);
        return;
    }

    box = directivesTable.rows[rowNum].cells[colNum].firstChild;

    return box.checked;
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
        let dir = directive;
        let sources = policy.directives[directive];

        switch (directive) {
            case "sandbox": {
                let sbx = document.querySelector("input#sandbox-enabled");
                let features = Array.from(document.querySelectorAll("td input.sandbox"));

                // In this context, sources are the keywords after the sandbox
                // directive, like sandbox allow-downloads.
                sbx.checked = true;

                for (let i = 0; i < sources.length; i++) {
                    let box = features.find(f => f.id == sources[i]);
                    box.checked = true;
                }

                // This isn't a source directive, so skip it.
                continue;
            }
            case "report-uri":
            case "base-uri":
                continue;
            // I think I should just simplify these, there are already enough directives.
            case "script-src-elem":
            case "script-src-attr":
                dir = "script-src";
                break;
            case "style-src-elem":
            case "style-src-attr":
                dir = "style-src";
                break;
        }
        for (let i = 0; i < sources.length; i++) {
            let src = sources[i];
            switch (src) {
                case "unsafe-inline":
                case "'unsafe-inline'":
                    if (dir == "srcipt-src" || dir == "style-src")
                        src = "'inline'";
                    break;
            }
            setSourceCheckboxState(src, dir, true, className);
        }
    }
}

async function setCurrentViolations(data)
{
    for (let directive in data) {
        for (let i = 0; i < data[directive].length; i++) {
            let src = data[directive][i];
            let dir = directive;
            switch (directive) {
                case "script-src-elem":
                case "script-src-attr":
                    dir = "script-src";
                    break;
                case "style-src-elem":
                case "style-src-attr":
                    dir = "style-src";
                    break;
            }
            setSourceCheckboxClass(src, dir, "violation");
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
            if (dirs[i] == "script-src" || dirs[i] == "style-src" && srcs[j] == "'inline'") {
                policy.directives[dirs[i]].push("'unsafe-inline'");
                continue;
            }
            policy.directives[dirs[i]].push(srcs[j]);
        }
    }

    // Now check for sandbox policies.
    let sbx = document.querySelector("input#sandbox-enabled");
    let features = Array.from(document.querySelectorAll("td input.sandbox.allow:checked")).map(f => f.id);

    // Append all the features enabled.
    policy.directives.sandbox = features;

    // If it is disabled, we can just throw the whole thing away.
    if (!sbx.checked) {
        delete policy.directives.sandbox
    }

    // Okay, give them to the Rules Manager
    RulesManager.addSessionRule(hostName, policy);
}

async function populateOriginList() {
    let url = await sidepanel.getActiveUrl();
    let tab = await sidepanel.getActiveTab();

    // Request a list of known origins.
    const origins = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_ORIGINS,
           data: {
                id: tab.id
        }
    });

    Array.from(originList.children).forEach(o => originList.removeChild(o));

    for (let i = 0; i < origins.length; i++) {
        let opt = document.createElement("option");
        opt.textContent = origins[i];
        opt.value = origins[i];
        opt.selected = url.origin == origins[i];
        originList.add(opt);
    }
}

async function populateServerPolicy() {
    let url = await sidepanel.getActiveUrl();
    let tab = await sidepanel.getActiveTab();

    // Request a list of known origins.
    const headers = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_HEADERS,
           data: {
                id: tab.id
        }
    });

    servercsp.value = headers.length == 0 ? "none" : "";
    for (let i = 0; i < headers.length; i++) {
        servercsp.value += headers[i];
        servercsp.value += "\n";
    }
}

async function updateReport() {
    let url = await sidepanel.getActiveUrl();
    let tab = await sidepanel.getActiveTab();

    // Remove any current rules.
    resetDirectivesTable();
    resetSandboxDirectives();

    // Fetch current rules.
    await getCurrentRules(url.host);

    // Request a list of violations.
    const violations = await chrome.runtime.sendMessage({
        command: MessageTypes.REQ_POLICY,
           data: {
                id: tab.id
        }
    });

    setCurrentViolations(violations);
    populateOriginList();
    populateServerPolicy();
};

resetDirectivesTable();
populateOriginList();
updateReport();
