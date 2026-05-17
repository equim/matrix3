import * as sidepanel from '/include/sidepanel.js'
import Options from '/include/options.js'

const optionElements = document.querySelectorAll(".option");
const options = await Options.get();

function syncOptionChanges(event) {
    switch (event.target.type) {
        case "checkbox": {
            options[event.target.id] = event.target.checked;
            break;
        }
        case "range": {
            options[event.target.id] = parseInt(event.target.value);
            break;
        }
        case "select-one": {
            options[event.target.id] = event.target.value;
            break;
        }
    }
    chrome.storage.sync.set({ options: options });
    sidepanel.applyOptions();
}

// Reflect cached options into form state. Called once at startup and again
// whenever another window mutates options.
function updateOptions() {
    for (let i = 0; i < optionElements.length; i++) {
        switch (optionElements[i].type) {
            case "checkbox": {
                optionElements[i].checked = options[optionElements[i].id];
                break;
            }
            case "range": {
                optionElements[i].value = options[optionElements[i].id];
                break;
            }
            case "select-one": {
                if (options[optionElements[i].id])
                    optionElements[i].value = options[optionElements[i].id];
                break;
            }
        }
    }
}

// Watch for changes, then sync them to the options object.
for (let i = 0; i < optionElements.length; i++)
    optionElements[i].addEventListener("change", syncOptionChanges);

Options.addUpdateListener(() => updateOptions());
updateOptions();
