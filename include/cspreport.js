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
        switch (uri) {
            case "about":
            case "data":
            case "blob":
            case "eval":
            case "wasm-eval":
                uri += ":";
                break;
            case "inline":
                uri = "unsafe-inline:";
        }

        try {
            return new URL(uri);
        } catch (e) {
            console.log("This uri failed:",uri,e);
            throw(e);
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
        if (typeof CspReport.#requestBodyDecode._textdec === 'undefined') {
            CspReport.#requestBodyDecode._textdec = new TextDecoder("utf-8");
        }
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
}

