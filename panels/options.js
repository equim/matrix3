import * as sidepanel from '/include/sidepanel.js'

const optionElements = document.querySelectorAll(".option");

function syncOptionChanges(event) {
    switch (event.target.type) {
        case "checkbox": {
            sidepanel.options[event.target.id] = event.target.checked;
            break;
        }
        case "range": {
            sidepanel.options[event.target.id] = parseInt(event.target.value);
            break;
        }
        case "select-one": {
            sidepanel.options[event.target.id] = event.target.value;
            break;
        }
    }
    chrome.storage.sync.set({ options: sidepanel.options });
    sidepanel.applyOptions();
}

for (let i = 0; i < optionElements.length; i++) {
    // Watch for changes, then sync it to options object.
    optionElements[i].addEventListener("change", syncOptionChanges);

    // Initialize form state from options.
    switch (optionElements[i].type) {
        case "checkbox": {
            optionElements[i].checked = sidepanel.options[optionElements[i].id];
            break
        }
        case "range": {
            optionElements[i].value = sidepanel.options[optionElements[i].id];
            break;
        }
        case "select-one": {
            if (sidepanel.options[optionElements[i].id])
                optionElements[i].value = sidepanel.options[optionElements[i].id];
            break;
        }
    }
}
