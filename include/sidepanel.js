import Rules from '/include/rules.js'

export let current = await chrome.windows.getCurrent();
export let { options } = await chrome.storage.sync.get("options");

const panel = document.getElementById("panel");
const { path } = await chrome.sidePanel.getOptions({});

export let RulesManager = new Rules();

const sidepanelPages = {
    "Report": "panels/report.html",
     "Rules": "panels/manage.html",
    "Groups": "panels/groups.html",
   "Options": "panels/options.html",
    "Export": "panels/export.html",
      "Help": "panels/help.html",
     "About": "panels/about.html",
};

if (typeof options === "undefined") {
    options = Object.create(null);
    await chrome.storage.sync.set({ options: options });
}

for (let page in sidepanelPages) {
    let opt = document.createElement("option");
    opt.innerText = page;
    opt.value = sidepanelPages[page];
    opt.selected = path == opt.value;
    panel.add(opt);
}

panel.addEventListener("change", event => {
    chrome.sidePanel.setOptions({ path: event.target.value });
});

export async function getActiveTab()
{
    let [ tab ] = await chrome.tabs.query({windowId: current.id, active: true});
    return tab;
}

// Any settings that need extra work to be applied, most should be just checked
// when required.
export async function applyOptions()
{
    await RulesManager.init();

    document.body.classList.toggle("hide-advanced", !options.advanced);

    if (options.defaultpolicy !== undefined)
        await RulesManager.applyDefaultPolicy(options.defaultpolicy);
}

await applyOptions();
