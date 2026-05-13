import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'

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
}

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
updateRuleTables();
