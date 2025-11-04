export async function getCurrentTabId()
{
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return tabs[0];
}

export function getMapKey(map, val) {
  return [...map].find(([key, value]) => val === value)[0];
}

export function clearTable(table, hasHdr) {
    let rows = Array.from(table.rows);
    for (let i = !!hasHdr; i < rows.length; i++) {
        table.deleteRow(-1);
    }
}
