import {Cryo_AllMessageIdentifier} from "../CryoMessage/CryoMessage.js";
import Guard from "./Guard.js";

class MessageGuardError extends Error {
    constructor(pMessage: string) {
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
    private static message_types: Cryo_AllMessageIdentifier[] = ["data", "mktopic", "error", "rmtopic", "success", "shutdown", "subscribe", "unsubscribe"];

    public static ValidateMessage(param: string): asserts param is Cryo_AllMessageIdentifier {
        Guard.AgainstNullish(param, "Passed message type was null!");
        if (!this.message_types.includes(<"error" | "success" | "subscribe" | "unsubscribe" | "data" | "mktopic" | "rmtopic" | "shutdown">param)) {
            throw new MessageGuardError(`Passed message type is invalid!`);
        }
    }
}