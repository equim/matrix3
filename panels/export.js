import * as utils from '/include/utils.js'
import * as sidepanel from '/include/sidepanel.js'

const outputElement = document.getElementById("export");
const loadElement = document.getElementById("import");

let rules = sidepanel.RulesManager.getAllRules();

outputElement.value = JSON.stringify(rules);

loadElement.addEventListener("click", async (ev) => {
    alert("FIXME");
});
