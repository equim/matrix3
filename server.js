import { MessageTypes } from '/include/commands.js'

export default class RequestServer {
    tracker;

    constructor(tracker) {
        this.tracker = tracker;
        chrome.runtime.onMessage.addListener(this.messageHandler.bind(this));
    }

    messageHandler(request, sender, sendResponse) {
        if (typeof request.command === 'undefined')
            return;

        switch (request.command) {
            case MessageTypes.REQ_POLICY: {
                sendResponse(this.tracker.getDirectives(request.data.id, request.data.domain));
                break;
            }
            case MessageTypes.REQ_HEADERS: {
                sendResponse(this.tracker.getServerPolicy(request.data.id, request.data.domain));
                break;
            }
        }

        return;
    }
}
