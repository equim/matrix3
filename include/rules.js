import Policy from '/include/policy.js'
import { MessageTypes } from '/include/commands.js'

// A declarativeNetRequest rule (session or dynamic).
class Rule {
    id;
    priority;
    isSession;
    action = {};
    condition = {};

    constructor(rule, session = false)
    {
        this.id = rule?.id;
        this.action.type = "modifyHeaders";
        this.action.responseHeaders = [{
            header: "Content-Security-Policy",
            operation: "set",
        }];
        this.condition.resourceTypes = [
            "main_frame", "sub_frame"
        ];
        this.condition.urlFilter = rule?.condition?.urlFilter;
        this.action.responseHeaders[0].value = rule?.action?.responseHeaders[0]?.value;
        this.priority = rule?.priority;
        this.isSession = session;
    };

    set host(host) {
        this.condition.urlFilter = "||" + host + "^";
    }

    get host() {
        return this.condition.urlFilter?.slice(2, -1);
    }

    get policy() {
        return this.toPolicy();
    }

    toPolicy() {
        let csp = new Policy();
        return csp.fromHeader(this.action.responseHeaders[0].value);
    }

    fromPolicy(policy) {
        this.action.responseHeaders[0].value = policy.toHeader();
    }

    toRule() {
        return {
            id: this.id,
            action: this.action,
            condition: this.condition,
            priority: this.priority,
        };
    }
}

class Ruleset {
    resource;
    id;
    enabled;
    json;

    constructor(resource) {
        this.resource = resource;
        this.id       = resource.id;
        this.enabled  = resource.enabled;
        this.url      = chrome.runtime.getURL(resource.path);
    }

    async enableRuleset() {
        await chrome.declarativeNetRequest.updateEnabledRulesets({
            enableRulesetIds: [ this.id ],
        });
        return this.enabled = await this.isEnabled();
    }

    async disableRuleset() {
        // Don't allow required rulesets to be disabled.
        if (this.isRequired())
            return false;

        await chrome.declarativeNetRequest.updateEnabledRulesets({
            disableRulesetIds: [ this.id ],
        });

        return this.enabled = ! await this.isEnabled();
    }

    async isEnabled() {
        let rulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
        this.enabled = rulesets.includes(this.id);
        return this.enabled;
    }

    isRequired() {
        return this.id == "base";
    }

    async #load() {
        if (this.json)
            return true;

        try {
            const response = await fetch(this.url);

            if (response.ok != true)
                return false;

            let [data] = await response.json();

            this.json = data;
            return true;
        } catch (e) {
            return false;
        }
    }

    async toPolicy()
    {
        let policy = new Policy();
        let csp;

        await this.#load();

        csp = this.json?.action?.responseHeaders?.find(r => r.header == "Content-Security-Policy");
        if (!csp)
            return policy;
        if (csp.operation != "set")
            return policy;

        return policy.fromHeader(csp.value);
    }
}

// This class will manage rules, and handle translating them between different forms.
export default class Rules {
    #staticRulesets;
    #id;
    #rules;

    // Map the defaultpolicy option slider (0-4) to the static rulesets that
    // should be enabled alongside the always-on `base`. Additive -- higher
    // levels stack rulesets rather than replacing them.
    static PolicyRulesets = [
        ["permissive"],              // 0: Off
        ["firstparty"],              // 1: First Party
        ["sandbox"],                 // 2: Sandbox
        ["sandbox", "firstparty"],   // 3: First Party Sandboxed
        ["strict"],                  // 4: Strict
    ];

    constructor() {
        this.#id = 0;
    }

    async applyDefaultPolicy(level) {
        await this.setEnabledRulesets(Rules.PolicyRulesets[level] ?? []);
    }

    async init() {
        let dynamic = await chrome.declarativeNetRequest.getDynamicRules();
        let session = await chrome.declarativeNetRequest.getSessionRules();

        this.#rules = [
            ...dynamic.map(r => new Rule(r)),
            ...session.map(r => new Rule(r, true)),
        ];
        this.#staticRulesets = [];

        // Track the highest ID in use to avoid collisions.
        for (let r of this.#rules) {
            if (r.id > this.#id)
                this.#id = r.id;
        }

        // Chrome's API doesn't list disabled rulesets, so enumerate them from the manifest.
        for (const resource of chrome.runtime.getManifest().declarative_net_request.rule_resources) {
            this.#staticRulesets.push(new Ruleset(resource));
        }

        for (let ruleset of this.#staticRulesets) {
            // Sync current state and probe internal rule IDs.
            await ruleset.isEnabled();
            await ruleset.toPolicy();
            if (ruleset.json?.id > this.#id)
                this.#id = ruleset.json.id;
        }
    }

    #getNextId() {
        return ++this.#id;
    }

    // Wrap dNR mutation APIs so every change broadcasts NOTIFY_RULES to
    // sidepanels in other windows (their `#rules` mirror is now stale).
    async #updateSessionRules(opts) {
        await chrome.declarativeNetRequest.updateSessionRules(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    async #updateDynamicRules(opts) {
        await chrome.declarativeNetRequest.updateDynamicRules(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    async #updateEnabledRulesets(opts) {
        await chrome.declarativeNetRequest.updateEnabledRulesets(opts);
        chrome.runtime.sendMessage({ command: MessageTypes.NOTIFY_RULES }).catch(() => {});
    }

    #findSessionForHost(hostName) {
        return this.#rules.find(r =>  r.isSession && r.host == hostName);
    }

    #findDynamicForHost(hostName) {
        return this.#rules.find(r => !r.isSession && r.host == hostName);
    }

    #removeRule(id) {
        this.#rules = this.#rules.filter(r => r.id != id);
    }

    // Empty template rule seeded with the active default ruleset's policy.
    async getEmptyRule(hostName) {
        let rule = new Rule();
        let policy = new Policy();
        let enabledRulesets = this.#staticRulesets.filter(r => r.enabled && !r.isRequired());

        for (let ruleset of enabledRulesets) {
             const p = await ruleset.toPolicy();
             for (const [dir, sources] of Object.entries(p.directives)) {
                 let isRedundant = true;

                 if (isRedundant && dir !== "default-src")
                     isRedundant = false;
                 if (isRedundant && sources[0] !== "'none'")
                     isRedundant = false;
                 if (isRedundant && policy.directives[dir]?.[0] !== "'none'")
                     isRedundant = false;

                 if (!isRedundant) {
                     policy.directives[dir] = [...sources];
                 }
             }
        }

        rule.id = this.#getNextId();
        rule.priority = 2;
        rule.fromPolicy(policy);
        if (hostName) {
            rule.host = hostName;
        }
        return rule;
    }

    // Install rulePolicy as a session rule for hostName, replacing any prior
    // session. Any existing dynamic stays put; the session's priority is
    // bumped above it so the session wins at runtime, and Abandon can then
    // delete the session to restore the dynamic.
    async addSessionRule(hostName, rulePolicy) {
        let rule = await this.getEmptyRule(hostName);
        let oldSession = this.#findSessionForHost(hostName);
        let oldDynamic = this.#findDynamicForHost(hostName);

        // Point report-uri at our extension's WAR so report POSTs succeed locally
        // instead of logging ERR_BLOCKED_BY_CLIENT against the placeholder URL.
        rulePolicy.directives["report-uri"] = [chrome.runtime.getURL("csp-report")];

        rule.fromPolicy(rulePolicy);
        rule.isSession = true;
        if (oldDynamic)
            rule.priority = oldDynamic.priority + 1;

        if (oldSession)
            this.#removeRule(oldSession.id);

        this.#rules.push(rule);

        await this.#updateSessionRules({
            removeRuleIds: oldSession ? [oldSession.id] : [],
            addRules: [ rule.toRule() ],
        });
    }

    // Delete the session rule for hostName (if any); any dynamic rule stays put.
    async abandonSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);

        if (!rule) {
            console.error("rules", `attempted to abandon non-existant session rule for ${hostName}`);
            return;
        }

        await this.delSessionRule(rule);
    }

    async delSessionRule(rule) {
        await this.#updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: []
        });
        this.#removeRule(rule.id);
    }

    async delDynamicRule(rule) {
        await this.#updateDynamicRules({
            removeRuleIds: [rule.id],
            addRules: []
        });
        this.#removeRule(rule.id);
    }

    // Wipe every session and dynamic rule (two batched API calls). Queries
    // Chrome directly so it doesn't need a fresh init(). Static rulesets
    // are left alone.
    async resetAllRules() {
        let session = await chrome.declarativeNetRequest.getSessionRules();
        let dynamic = await chrome.declarativeNetRequest.getDynamicRules();

        await this.#updateSessionRules({
            removeRuleIds: session.map(r => r.id),
            addRules: [],
        });
        await this.#updateDynamicRules({
            removeRuleIds: dynamic.map(r => r.id),
            addRules: [],
        });

        this.#rules = [];
    }

    // Remove every session and dynamic rule for this host.
    async resetHostRules(hostName) {
        let matches = this.#rules.filter(r => r.host == hostName);
        for (let rule of matches) {
            if (rule.isSession)
                await this.delSessionRule(rule);
            else
                await this.delDynamicRule(rule);
        }
    }

    // Demote the host's dynamic rule into a session rule (inverse of Commit).
    // No-op if there's no dynamic rule, or if a session rule already exists
    // for this host -- the user should commit or abandon that first.
    async uncommitDynamicRulesForHost(hostName) {
        let rule = this.#findDynamicForHost(hostName);
        let session = this.#findSessionForHost(hostName);
        if (!rule || session)
            return;
        await this.#updateSessionRules({
            removeRuleIds: [],
            addRules: [rule.toRule()],
        });
        await this.#updateDynamicRules({
            removeRuleIds: [rule.id],
            addRules: [],
        });
        rule.isSession = true;
    }

    // Promote the host's session rule into a dynamic rule, replacing any
    // existing dynamic. Priority is demoted back to the prior dynamic's
    // level so commits don't drift priorities upward.
    async commitSessionRulesForHost(hostName) {
        let rule = this.#findSessionForHost(hostName);
        let prev = this.#findDynamicForHost(hostName);
        if (!rule)
            return;
        if (prev)
            rule.priority = prev.priority;
        await this.#updateDynamicRules({
            removeRuleIds: prev ? [prev.id] : [],
            addRules: [rule.toRule()],
        });
        await this.#updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: [],
        });
        rule.isSession = false;
        if (prev)
            this.#removeRule(prev.id);
    }

    // Rule for matching host, preferring session over dynamic.
    getHostRule(hostName) {
        return this.#findSessionForHost(hostName) ?? this.#findDynamicForHost(hostName);
    }

    getRules() {
        return this.#rules;
    }

    getAllStaticRules() {
        return this.#staticRulesets;
    }

    // Enable exactly the named static rulesets (plus required ones); disable
    // every other non-required ruleset. One batched API call, atomic.
    async setEnabledRulesets(ids) {
        let wanted = new Set(ids);
        let enableRulesetIds = [];
        let disableRulesetIds = [];

        for (let r of this.#staticRulesets) {
            if (r.isRequired())
                continue;
            if (wanted.has(r.id))
                enableRulesetIds.push(r.id);
            else
                disableRulesetIds.push(r.id);
        }

        await this.#updateEnabledRulesets({
            enableRulesetIds,
            disableRulesetIds,
        });

        for (let r of this.#staticRulesets)
            await r.isEnabled();
    }

}
