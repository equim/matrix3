import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'

const RulesManager = sidepanel.RulesManager;
const outputElement = document.getElementById("export");
const loadElement = document.getElementById("import");
const downloadElement = document.getElementById("download");
const options = await Options.get();

async function buildExport() {
    let rules = RulesManager.getRules();
    return {
        session: rules.filter(r => r.isSession).map(r => r.toRule()),
        dynamic: rules.filter(r => !r.isSession).map(r => r.toRule()),
        options,
        enabledRulesets: await chrome.declarativeNetRequest.getEnabledRulesets(),
    };
}

async function refreshExport() {
    outputElement.value = JSON.stringify(await buildExport(), null, 2);
}

downloadElement.addEventListener("click", () => {
    const blob = new Blob([outputElement.value], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "matrix3.json";
    link.click();
    URL.revokeObjectURL(url);
});

loadElement.addEventListener("click", async () => {
    let blob;
    try {
        blob = JSON.parse(outputElement.value);
    } catch (e) {
        alert("Invalid JSON: " + e.message);
        return;
    }

    await RulesManager.replaceAllRules(blob.session ?? [], blob.dynamic ?? []);

    if (blob.options) {
        Object.assign(options, blob.options);
        await chrome.storage.sync.set({ options });
    }

    // base is always-enabled and skipped by setEnabledRulesets anyway, but
    // filter it out explicitly so a stray "base" in the blob is benign.
    if (blob.enabledRulesets)
        await RulesManager.setEnabledRulesets(
            blob.enabledRulesets.filter(id => id !== "base")
        );

    // applyOptions re-applies the defaultpolicy ruleset and the advanced class.
    await sidepanel.applyOptions();
    await refreshExport();
});

Options.addUpdateListener(() => refreshExport());

await refreshExport();
