This is matrix³, an experimental mv3 content policy manager.

This is extension is inspired by [uMatrix](https://github.com/gorhill/uMatrix),
but built on `declarativeNetRequest`.

It looks like this, it adds a sidepanel that lets you enable or disable web
features.

<img width="2064"
     height="1196"
     src="https://github.com/user-attachments/assets/bccf9075-5853-4d5e-a828-e9ccce3217af" />

## Installation

1. Clone or download this repository.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and point it at the repository root.

## Usage

- Open the sidepanel via the matrix³ toolbar icon.

If this is your first time using the extension, choose a default policy in the
**Options** page.

- If a site isn't working, open the **Report** page.

The violations are highlighted, enable options until the site works. Click
**Reload** to reload the tab.

When you're happy with a host's settings, click **Commit** to make them
persistent. The **Rules** panel shows all dynamic and session rules; you can
delete individual rules from there.
