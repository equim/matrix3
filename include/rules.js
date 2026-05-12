import Policy from '/include/policy.js'

// An individual declarativeNetRequest Rule, both Session and Dynamic rules.
// You can differentiate between them with rule.isSession. Static rules are
// managed by Ruleset, not individual Rules.
// Note: This class is hardcoded to handle the rules this extension will
// generate, not arbitrary rules.
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
    path;
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
        // Dont allow required rulesets to be disabled.
        if (this.isRequired())
            return false;

        await chrome.declarativeNetRequest.updateEnabledRulesets({
            disableRulesetIds: [ this.id ],
        });

        return this.enabled = ! await this.isEnabled();
    }

    async isEnabled() {
        let rulesets = await chrome.declarativeNetRequest.getEnabledRulesets();
        this.enabled = await rulesets.includes(this.id);
        return this.enabled;
    }

    isRequired() {
        return this.id == "base";
    }

    async #load() {
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
    #dynamicRules;
    #sessionRules;
    #staticRulesets;
    #id;
    #allRules;

    constructor() {
        this.#id = 0;
    }

    async init() {
        this.#dynamicRules   = await chrome.declarativeNetRequest.getDynamicRules();
        this.#sessionRules   = await chrome.declarativeNetRequest.getSessionRules();
        this.#allRules       = this.#dynamicRules.map(r => new Rule(r));
        this.#allRules       = this.#allRules.concat(this.#sessionRules.map(r => new Rule(r, true)));
        this.#staticRulesets = [];
        for (let r of this.#allRules) {
            if (r.id > this.#id)
                this.#id = r.id;
        }

        // I think the only way to query disabled rulesets is to read them out of your manifest.
        chrome.runtime
              .getManifest()
              .declarative_net_request
              .rule_resources
              .forEach(r => this.#staticRulesets.push(new Ruleset(r)));

        // Make sure the enabled flags get set if available.
        for (let i = 0; i < this.#staticRulesets.length; i++) {
            await this.#staticRulesets[i].isEnabled();
            //console.log("rules", "rulesets", this.#staticRulesets[i], this.#staticRulesets[i].enabled);
        }
    }

    // Internal, choose the next available id
    #getNextId() {
        return ++this.#id;
    }

    // Get an empty template rule, only default policy.
    async getEmptyRule(hostName) {
        let rule = new Rule();
        let policy = new Policy();

        // Try to guess what the current default policy is.
        let defaultRule = this.#staticRulesets.find(r => r.enabled && !r.isRequired());

        // Try to load that rule to see what it does.
        if (defaultRule)
            policy = await defaultRule.toPolicy();

        rule.id = this.#getNextId();
        rule.priority = 2;
        rule.fromPolicy(policy);
        if (hostName) {
            rule.host = hostName;
        }
        return rule;
    }

    // Take a Policy() and Make it a session rule
    async addSessionRule(hostName, rulePolicy) {
        let rule = await this.getEmptyRule(hostName);
        let removeId = [];
        let oldRule = this.getHostRule(hostName);
        rule.fromPolicy(rulePolicy);
        this.#sessionRules.push(rule.toRule());
        this.#allRules.push(rule);
        if (oldRule)
            removeId.push(oldRule.id);
        await chrome.declarativeNetRequest.updateSessionRules({
            removeRuleIds: removeId,
            addRules: [ rule.toRule() ],
        });
    }

    async delSessionRule(rule) {
        await chrome.declarativeNetRequest.updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: []
        });
        this.#sessionRules = this.#sessionRules.filter(r => r.id != rule.id);
        this.#allRules = this.#allRules.filter(r => r.id != rule.id);
    }

    async delDynamicRule(rule) {
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [rule.id],
            addRules: []
        });
        this.#dynamicRules = this.#dynamicRules.filter(r => r.id != rule.id);
        this.#allRules = this.#allRules.filter(r => r.id != rule.id);
    }

    // Remove every session and dynamic rule for this host.
    async resetHostRules(hostName) {
        let matches = this.#allRules.filter(r => r.host == hostName);
        for (let rule of matches) {
            if (rule.isSession)
                await this.delSessionRule(rule);
            else
                await this.delDynamicRule(rule);
        }
    }

    // The session rule for matching host becomes a dynamic rule
    async commitSessionRulesForHost(hostName) {
        let rule = this.#allRules.find(r => r.isSession && r.host == hostName);
        if (!rule)
            return;
        await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [],
            addRules: [rule.toRule()],
        });
        await chrome.declarativeNetRequest.updateSessionRules({
            removeRuleIds: [rule.id],
            addRules: [],
        });
    }

    // return the Policy() for matching host
    getHostRule(hostName) {
        return this.#allRules.find(r => r.host == hostName);
    }

    getAllDirectives() {
        let keys = new Set();
        this.#allRules.forEach(r => Object.keys(r.policy.directives).forEach(k => keys.add(k)));
        return Array.from(keys);
    }

    getAllRules() {
        return this.#allRules;
    }

    getAllStaticRules() {
        return this.#staticRulesets;
    }

    enableStaticRuleset(id) {
        let rule = this.#staticRulesets.find(r => r.id == id);
        return rule.enableRuleset();
    }

    disableStaticRuleset(id) {
        let rule = this.#staticRulesets.find(r => r.id == id);
        return rule.disableRuleset();
    }

    setDefaultRuleset(id) {
        let toEnable  = this.#staticRulesets.filter(r => r.id == id);
        let toDisable = this.#staticRulesets.filter(r => r.id != id);
        toEnable.forEach(r => r.enableRuleset());
        toDisable.forEach(r => r.disableRuleset());
        return toEnable[0].isEnabled();
    }

}
