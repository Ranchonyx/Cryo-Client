import Guard from "./Guard.js";
class MessageGuardError extends Error {
    constructor(pMessage) {
        super(pMessage);
        Error.captureStackTrace ||= () => {
        };
        if (Error.captureStackTrace) {
            Error.captureStackTrace(this, MessageGuardError);
        }
        Object.setPrototypeOf(this, MessageGuardError.prototype);
    }
}
export default class MessageGuard {
    static message_types = ["data", "mktopic", "error", "rmtopic", "success", "shutdown", "subscribe", "unsubscribe"];
    static ValidateMessage(param) {
        Guard.AgainstNullish(param, "Passed message type was null!");
        if (!this.message_types.includes(param)) {
            throw new MessageGuardError(`Passed message type is invalid!`);
        }
    }
}
