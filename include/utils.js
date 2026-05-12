export async function getCurrentTabId()
{
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tabs[0];
}

export function getMapKey(map, val) {
  return [...map].find(([key, value]) => val === value)[0];
}

export function clearTable(table) {
    table.tBodies[0]?.replaceChildren();
}

// Sort tbody rows alphabetically by the first cell's text content. Header
// rows in <thead> are untouched.
export function sortTable(table) {
    let rows = Array.from(table.tBodies[0].rows);
    rows.sort((a, b) => a.cells[0].textContent.localeCompare(b.cells[0].textContent));
    for (let row of rows)
        row.parentNode.appendChild(row);
}

// Count the columns of a table by looking at its header row.
export function countTableCols(table) {
    return table.tHead.rows[0].cells.length;
}

// Return a property from each header cell, e.g. ('id') for column IDs or
// ('textContent') for column labels.
export function getTableColProps(table, prop) {
    return Array.from(table.tHead.rows[0].cells, c => c[prop]);
}

// Return a property from each body row's first cell — typically the row
// label, e.g. ('textContent') for row titles.
export function getTableRowProps(table, prop) {
    return Array.from(table.tBodies[0].rows, r => r.cells[0][prop]);
}

// Find the body row whose first-cell text matches `label`, or undefined.
export function findTableRow(table, label) {
    return Array.from(table.tBodies[0].rows).find(r => r.cells[0].textContent === label);
}

// Enforce single-checked semantics across a checkbox group. When `target`
// belongs to `group` and was just checked, uncheck every other member.
// `group` may be a NodeList, array, or any iterable of checkboxes.
export function checkboxMutex(group, target) {
    let boxes = Array.from(group);

    if (!target.checked)
        return;
    if (!boxes.includes(target))
        return;

    for (let box of boxes)
        if (box !== target) box.checked = false;
}
