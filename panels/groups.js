import * as sidepanel from '/include/sidepanel.js'

const groupsContainer = document.getElementById('groups');
const newnameInput = document.getElementById('newname');
const groupTemplate = document.getElementById('group-template');
const originTemplate = document.getElementById('origin-template');

sidepanel.options.groups ??= {};
sidepanel.options.groups.Ignore ??= [];

async function saveGroups() {
    await chrome.storage.sync.set({ options: sidepanel.options });
}

function updateGroupsDisplay() {
    groupsContainer.replaceChildren();

    for (let [name, origins] of Object.entries(sidepanel.options.groups)) {
        let g = groupTemplate.content.cloneNode(true).firstElementChild;
        let ul = g.querySelector('ul');
        let input = g.querySelector('.neworigin');

        g.querySelector('.group-name').textContent = name;
        g.querySelector('.delgroup').addEventListener('click', () => deleteGroup(name));
        g.querySelector('.addorigin').addEventListener('click', () => addOrigin(name, input.value));

        for (let origin of origins) {
            let o = originTemplate.content.cloneNode(true).firstElementChild;
            o.querySelector('.origin-name').textContent = origin;
            o.querySelector('.delorigin').addEventListener('click', () => removeOrigin(name, origin));
            ul.appendChild(o);
        }

        groupsContainer.appendChild(g);
    }
}

async function addGroup() {
    let name = newnameInput.value.trim();

    if (!name)
        return;
    if (name in sidepanel.options.groups)
        return;

    sidepanel.options.groups[name] = [];
    newnameInput.value = '';
    await saveGroups();
    updateGroupsDisplay();
}

async function deleteGroup(name) {
    delete sidepanel.options.groups[name];
    await saveGroups();
    updateGroupsDisplay();
}

async function addOrigin(group, origin) {
    origin = origin.trim();

    if (!origin)
        return;
    if (sidepanel.options.groups[group].includes(origin))
        return;

    sidepanel.options.groups[group].push(origin);
    await saveGroups();
    updateGroupsDisplay();
}

async function removeOrigin(group, origin) {
    sidepanel.options.groups[group] = sidepanel.options.groups[group].filter(x => x !== origin);
    await saveGroups();
    updateGroupsDisplay();
}

document.getElementById('addgroup').addEventListener('click', () => addGroup());

updateGroupsDisplay();
