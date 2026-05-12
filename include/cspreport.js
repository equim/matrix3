// Parser for intercepted csp_report requests.
export default class CspReport {
    #request;
    #body;
    initiator;
    report;
    blockeduri;
    docuri;
    tabId;

    #decodeReportUri(uri) {
        if (uri === "null") {
            // Sandboxed contexts, form resubmits, anonymous requests.
            console.log("cspreport", "null uri, skipping");
            return null;
        }
        if (CspReport.protocolSource(uri + ":") !== undefined)
            uri += ":";

        try {
            return new URL(uri);
        } catch (e) {
            console.log("cspreport", "unexpected unparseable uri:", uri, e);
            return null;
        }
    }

    constructor(details) {
        this.#request = details;

        // Decode what chrome is reporting.
        this.#body = CspReport.#requestBodyDecode(this.#request.requestBody);
        this.report = JSON.parse(this.#body);
        this.tabId = details.tabId;
        this.initiator = this.#decodeReportUri(details.initiator);

        // We only care about this property.
        this.report = this.report["csp-report"];

        this.docuri = this.#decodeReportUri(this.report["document-uri"]);

        // This might be a URI, or might be a keyword like "inline".
        this.blockeduri = this.#decodeReportUri(this.report["blocked-uri"]);

        console.log("cspreport", "blocked", this.report["blocked-uri"], "for", this.report["effective-directive"], this);
    }

    static #requestBodyDecode(body) {
        // We only need one of these, so initialize it now. I think as this
        // method is static, it will be shared between all callers.
        CspReport.#requestBodyDecode._textdec ??= new TextDecoder("utf-8");
        return body.raw.reduce((a, c) => CspReport.#requestBodyDecode._textdec.decode(c.bytes), "");
    }

    get directive() {
        return this.report["effective-directive"];
    }

    get blocked() {
        return this.blockeduri;
    }

    isOutermost() {
        return this.#request.frameType === "outermost_frame";
    }

    // CSP report's "blocked-uri" can be a real URL or a pseudo-scheme used
    // by the browser to represent opaque sources (inline scripts, eval,
    // etc). After parsing through new URL(), the .protocol of those
    // pseudo-schemes maps to the CSP source-list keyword that allows them.
    static protocolSource(protocol) {
        switch (protocol) {
            case "inline:":
                return "'unsafe-inline'";
            case "eval:":
                return "'unsafe-eval'";
            case "wasm-eval:":
                return "'wasm-unsafe-eval'";
            case "about:":
            case "data:":
            case "blob:":
                return protocol;
        }
    }
}

