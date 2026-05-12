# matrix³

This is matrix³, an experimental mv3 content policy manager.

This extension is inspired by [uMatrix](https://github.com/gorhill/uMatrix),
but built on `declarativeNetRequest` for modern browsers.

It looks like this -- it adds a sidepanel that lets you enable or disable web
features.

<img width="2064"
     height="1196"
     src="https://github.com/user-attachments/assets/bccf9075-5853-4d5e-a828-e9ccce3217af" />

## Installation

1. Clone or download this repository.
2. Open `chrome://extensions`, enable **Developer mode**, click **Load
   unpacked**, and point it at the repository root.

## Usage

Open the sidepanel via the matrix³ toolbar icon. If this is your first time
using the extension, choose a default policy in the **Options** page.

If a site isn't working, open the **Report** page. Violations are highlighted;
enable options until the site works. Click **Reload** to reload the tab.

When you're happy with a host's settings, click **Commit** to make them
persistent. The **Rules** panel shows all dynamic and session rules; you can
delete individual rules from there.

## Policies

The default policy is **Sandbox**, which sandboxes the document -- many pages
will fail to render correctly. That's intentional; adjust per-host as you go.

If you find it too restrictive, change the level in **Options**. The policies
are described here.

### Off (level 0)

Nothing is blocked by default. If you want to reduce permissions for a specific
site, you need to adjust it in the **Report** tab.

### First Party (level 1)

First-party scripts, styles, and other resources are generally allowed,
including `'unsafe-inline'` for scripts and styles. Third-party resources are
blocked unless you give them permission in the **Report** tab.

### Sandbox (level 2)

The `sandbox` attribute is applied to every document -- no scripts, forms,
popups, or top navigation. Add specific `allow-*` exceptions in the
**Sandbox** section of the **Report** tab if you need them.

If you want to disable the sandbox attribute for a site, you can disable it
and switch to standard source directives (e.g. set `default-src` to `'none'`
for a strict policy).

### First Party Sandboxed (level 3)

Combines First Party and Sandbox: first-party resources are generally
allowed, but the document is also sandboxed. Use this when you trust the
first-party code but want the extra isolation.

### Strict (level 4)

Effectively everything is disabled -- `default-src` is set to `'none'`.

Violations will be highlighted in the **Report** tab, and you can enable
checkboxes until the site works.
