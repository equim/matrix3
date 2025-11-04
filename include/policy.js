// This class is just a simple representation of a csp policy.
import Rules from '/include/rules.js'

// The default blank policy you get from new Policy()
const defaultPolicy = {
    "default-src": [ "'none'" ],
    "report-uri": [ "https://_matrix3.internal/csp-report" ],
};

export default class Policy {
    // Setup all the default directives we use. You can override these if you want.
    directives = structuredClone(defaultPolicy);

    // Initialize a Policy from a Rule object, these are what the RuleManager tracks.
    fromDynamicRule(ruleObj) {
        this.directives = {};
        fromHeader(ruleObj.action.responseHeaders.value);
    }

    // Initialize from a HTTP header.
    fromHeader(headerString) {
        let headerTokens = headerString.trim().split(';').filter(f => f.length);

        // Reset directives, because we're importing from a header.
        this.directives = {};

        // Add each directive to our object.
        for (let i = 0; i < headerTokens.length; i++) {
            const directive = headerTokens[i].trim().split(/\s+/);
            const directiveName = directive.shift();
            this.directives[directiveName] = directive;
        }
        return this;
    }

    // Convert from our internal representation into a HTTP header.
    toHeader() {
        let headerString = "";
        for (let directive in this.directives) {
            headerString += directive;
            headerString += " ";
            headerString += this.directives[directive].join(" ");
            headerString += "; ";
        }
        return headerString;
    }
}
