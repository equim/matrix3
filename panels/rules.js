import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'
import { MessageTypes } from '/include/commands.js'

let RulesManager = sidepanel.RulesManager;

const dynamicTbl = document.getElementById('dynamic');
const sessionTbl = document.getElementById('session');
const staticTbl = document.getElementById('static');

async function updateRuleTables() {
    let rules = RulesManager.getRules();
    let base  = RulesManager.getAllStaticRules();

    utils.clearTable(dynamicTbl);
    utils.clearTable(sessionTbl);

    for (let rule of rules) {
        let tbl = dynamicTbl;
        if (rule.isSession)
            tbl = sessionTbl;
        let row = tbl.insertRow(-1);
        let chk = document.createElement("input");
        chk.type = "checkbox";
        chk.checked = true;
        chk.className = "rule";
        row.insertCell(-1).appendChild(chk);
        row.insertCell(-1).innerText = rule.id;
        row.insertCell(-1).innerText = rule.host;
        row.insertCell(-1).innerText = rule.policy.toHeader();
    }

    utils.clearTable(staticTbl);

    for (let ruleset of base) {
        let row = staticTbl.insertRow(-1);
        let chk = document.createElement("input");
        chk.type = "checkbox";
        chk.checked = await ruleset.isEnabled();
        chk.disabled = true;
        chk.className = "rule";
        chk.title = "Adjust Rulesets in Options...";
        row.insertCell(-1).appendChild(chk);
        row.insertCell(-1).innerText = ruleset.id;
    }

    applyFilter();
    document.getElementById('reset').disabled = rules.length === 0;
}

function applyFilter() {
    const filterText = document.getElementById('filter').value.toLowerCase();
    const tables = [dynamicTbl, sessionTbl];
    for (let table of tables) {
        for (let row of table.rows) {
            if (row.innerText.toLowerCase().includes(filterText)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        }
    }
}

document.getElementById('filter').addEventListener('input', applyFilter);

document.getElementById('apply').addEventListener("click", async () => {
    for (let row of sessionTbl.rows)
        if (!row.cells[0].firstChild.checked)
            await RulesManager.delSessionRule({id: parseInt(row.cells[1].innerText)});

    for (let row of dynamicTbl.rows)
        if (!row.cells[0].firstChild.checked)
            await RulesManager.delDynamicRule({id: parseInt(row.cells[1].innerText)});
});

document.getElementById('query').addEventListener("click", async () => {
    await RulesManager.init();
    updateRuleTables();
});
document.getElementById('reset').addEventListener("click", async () => {
    await RulesManager.resetAllRules();
    updateRuleTables();
});

chrome.runtime.onMessage.addListener((msg) => {
    switch (msg.command) {
        case MessageTypes.NOTIFY_RULES:
            // Another window mutated dNR rules; our mirror is stale.
            RulesManager.init().then(() => updateRuleTables());
            break;
    }
});

updateRuleTables();
