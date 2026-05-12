import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'

let RulesManager = sidepanel.RulesManager;

const dynamicTbl = document.getElementById('dynamic');
const sessionTbl = document.getElementById('session');
const staticTbl = document.getElementById('static');

async function updateRuleTables() {
    let rules = RulesManager.getAllRules();
    let base  = RulesManager.getAllStaticRules();

    utils.clearTable(dynamicTbl);
    utils.clearTable(sessionTbl);

    for (let i = 0; i < rules.length; i++) {
        let tbl = rules[i].isSession
                    ? sessionTbl
                    : dynamicTbl;
        let row = tbl.insertRow(-1);
        let chk = document.createElement("input");
        chk.type = "checkbox";
        chk.checked = true;
        chk.className = "rule";
        row.insertCell(-1).appendChild(chk);
        row.insertCell(-1).innerText = rules[i].id;
        row.insertCell(-1).innerText = rules[i].host;
        row.insertCell(-1).innerText = rules[i].policy.toHeader();
    }

    utils.clearTable(staticTbl);

    for (let i = 0; i < base.length; i++) {
        let row = staticTbl.insertRow(-1);
        let chk = document.createElement("input");
        chk.type = "checkbox";
        chk.checked = await base[i].isEnabled();
        chk.disabled = base[i].isRequired();
        chk.className = "rule";
        row.insertCell(-1).appendChild(chk);
        row.insertCell(-1).innerText = base[i].id;
    }
}

document.getElementById('apply').addEventListener("click", async () => {
    let toDisable;
    let toEnable;
    toDisable = Array.from(sessionTbl.rows, f => f.firstChild)
                         .filter(f => !f.firstChild.checked)
                         .map(f => parseInt(f.nextSibling.innerText));
    toDisable.forEach(rid => RulesManager.delSessionRule({id: rid}));
    toDisable = Array.from(dynamicTbl.rows, f => f.firstChild)
                         .filter(f => !f.firstChild.checked)
                         .map(f => parseInt(f.nextSibling.innerText));
    toDisable.forEach(rid => RulesManager.delDynamicRule({id: rid}));

    // Now handle static rulesets
    toEnable = Array.from(staticTbl.rows, f => f.firstChild)
                        .filter(f => f.firstChild.checked)
                        .map(f => f.nextSibling.innerText);
    toDisable = Array.from(staticTbl.rows, f => f.firstChild)
                        .filter(f => !f.firstChild.checked)
                        .map(f => f.nextSibling.innerText);

    toEnable.forEach(r => RulesManager.enableStaticRuleset(r));
    toDisable.forEach(r => RulesManager.disableStaticRuleset(r));
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

