// This class is just a simple representation of a csp policy.

// The default blank policy you get from new Policy()
const defaultPolicy = {
    "report-uri": [ "https://_matrix3.internal/csp-report" ],
};

export default class Policy {
    // Default directives -- override per instance as needed.
    directives = structuredClone(defaultPolicy);

    // Server-supplied directives we don't manage in the UI but want to
    // preserve in our generated rule so we don't silently weaken security.
    static AllowedPassthruDirectives = new Set([
        "frame-ancestors",
        "form-action",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
        "require-trusted-types-for",
        "trusted-types",
        "base-uri",
    ]);

    // Initialize from a HTTP header.
    fromHeader(headerString) {
        let headerTokens = headerString.trim().split(';').filter(f => f.length);

        // Reset directives to a null-prototype object to prevent pollution.
        this.directives = Object.create(null);

        for (let i = 0; i < headerTokens.length; i++) {
            const directive = headerTokens[i].trim().split(/\s+/);
            const directiveName = directive.shift().toLowerCase();

            if (!directiveName)
                continue;

            // Per W3C, only the first occurrence of a directive is honored.
            if (directiveName in this.directives) {
                console.log("policy", "skipping duplicate directive", directiveName);
                continue;
            }

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
