# Testing

## Panels

### Report
    - A non http/https page disables the panel.
    - Changing tab updates the report.
    - Two windows open on the same report, updating one updates the other.

    - Clicking commit converts the current session rule into a dynamic rule.
    - Clicking uncommit converts the current dynamic rule into a session rule.
    - Abandon discards any active session rule, so the dynamic (or default) rule takes over.
    - Reset removes all rules for this origin, only the default rule remains.
    - Reload reloads the tab
        - Holding shift while clicking reload ignores cache.
    - Unblock checks all violations
        - Ignored origins are skipped
        - There is sane handling of 'none'

#### Origin
    - A page with two or more lists all origins.
    - Switching origin and hitting reload maintains origin.
    - Changing origin updates report.

#### Groups
    - The Ignore group should not be listed in dropdown.
    - Selecting a group and clicking trust adds all origins to common srcs as a new *sesion* rule.
    - Clicking Untrust removes all srcs from origins (TODO: do we really need an untrust action?)
    - If there are no groups other than Ignore, the Groups section should not be displayed.

#### Directives
    - If there are known violations they are hilighted Orange.

#### Sandbox

#### Server Policy

### Rules
    - Filtering works
    - Removing works for Session rules and Dynamic rules
    - Removing more than 5 rules prompts if confirmation enabled
    - Commit converts a session rule to a dyanmic rule.
    - Reset prompts if confirmation enabled.
    - Two windows with sidepanels open, adding/deleting a rule updates the list.
### Icon
    - Clicking the icon toggles sidepanel visibility in current window.
    - Right click -> Options should open the options panel in a tab.
        - Verify this tab syncs between open sidepanels.
