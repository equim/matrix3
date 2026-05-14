// Parser for intercepted csp_report requests.
export default class CspReport {
    initiator;
    report;
    blockeduri;

    #decodeReportUri(uri) {
        if (uri === "null")
            return null;

        // CSP keywords like 'inline' or 'eval' won't parse as URLs without a 
        // scheme. Prepending a colon makes them valid opaque URLs (e.g. 'eval:'),
        // which lets the URL constructor succeed and preserves the keyword in 
        // the .protocol property for later normalization in ViolationTracker.
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
        // Decode what chrome is reporting.
        let body = CspReport.#requestBodyDecode(details.requestBody);
        this.report = JSON.parse(body)["csp-report"];
        this.initiator = this.#decodeReportUri(details.initiator);

        // This might be a URI, or might be a keyword like "inline".
        this.blockeduri = this.#decodeReportUri(this.report["blocked-uri"]);

        console.log("cspreport", "blocked", this.report["blocked-uri"], "for", this.report["effective-directive"], this);
    }

    static #requestBodyDecode(body) {
        // Shared TextDecoder across all callers of this static method.
        CspReport.#requestBodyDecode._textdec ??= new TextDecoder("utf-8");
        const decoder = CspReport.#requestBodyDecode._textdec;
        let json = "";
        for (const {bytes} of body.raw ?? []) {
            if (bytes) json += decoder.decode(bytes, { stream: true });
        }
        return json + decoder.decode();
    }

    get directive() {
        return this.report["effective-directive"];
    }

    get blocked() {
        return this.blockeduri;
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

