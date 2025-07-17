import {
    CryoAllMessage,
    CryoDataMessage,
    CryoErrorMessage, CryoMakeTopicMessage, CryoRemoveTopicMessage,
    CryoShutdownMessage, CryoSubscriptionMessage,
    CryoSuccessMessage, CryoUnsubscribeMessage
} from "./CryoMessage.js";

interface CryoMessageFormatter<T extends CryoAllMessage> {
    Deserialize(value: string): T;

    Serialize(value: T): string;
}

//data::topic::timestamp::contents
class DataMessageFormatter implements CryoMessageFormatter<CryoDataMessage> {
    public Deserialize(value: string): CryoDataMessage {
        const [type, topic, data, timestamp] = value.split("::");
        if (type !== "data")
            throw new Error("Attempt to deserialize a non-data message!");

        try {
            const parsedData = JSON.parse(data);
            return {
                topic,
                data: parsedData,
                timestamp: parseInt(timestamp),
                type: "data"
            }
        } catch (ex) {
            throw new Error("Invalid JSON data in message body!");
        }
    }

    public Serialize(value: CryoDataMessage): string {
        return `data::${value.topic}::${JSON.stringify(value.data)}::${value.timestamp}`
    }
}

//shutdown::topic::timestamp::reason
class ShutdownMessageFormatter implements CryoMessageFormatter<CryoShutdownMessage> {
    public Deserialize(value: string): CryoShutdownMessage {
        const [type, topic, reason, timestamp] = value.split("::", 4);
        if (type !== "shutdown")
            throw new Error("Attempt to deserialize a non-shutdown message!");

        return {
            topic,
            reason,
            timestamp: parseInt(timestamp),
            type: "shutdown"
        }
    }

    public Serialize(value: CryoShutdownMessage): string {
        return `shutdown::${value.topic}::${value.reason}::${value.timestamp}`
    }
}

//error::timestamp::message
class ErrorMessageFormatter implements CryoMessageFormatter<CryoErrorMessage> {
    public Deserialize(value: string): CryoErrorMessage {
        const [type, message, timestamp] = value.split("::", 4);
        if (type !== "error")
            throw new Error("Attempt to deserialize a non-error message!");

        return {
            message,
            timestamp: parseInt(timestamp),
            type: "error"
        }
    }

    public Serialize(value: CryoErrorMessage): string {
        return `error::${value.message}::${value.timestamp}`
    }
}

//success::timestamp::message
class SuccessMessageFormatter implements CryoMessageFormatter<CryoSuccessMessage> {
    public Deserialize(value: string): CryoSuccessMessage {
        const [type, message, timestamp] = value.split("::", 4);
        if (type !== "success")
            throw new Error("Attempt to deserialize a non-success message!");

        return {
            message,
            timestamp: parseInt(timestamp),
            type: "success"
        }
    }

    public Serialize(value: CryoSuccessMessage): string {
        return `success::${value.message}::${value.timestamp}`
    }
}

//subscribe::timestamp::subscribe_to
class SubscribeMessageFormatter implements CryoMessageFormatter<CryoSubscriptionMessage> {
    public Deserialize(value: string): CryoSubscriptionMessage {
        const [type, subscribe_to, timestamp] = value.split("::", 4);
        if (type !== "subscribe")
            throw new Error("Attempt to deserialize a non-subscribe message!");

        return {
            subscribe_to,
            timestamp: parseInt(timestamp),
            type: "subscribe"
        }
    }

    public Serialize(value: CryoSubscriptionMessage): string {
        return `subscribe::${value.subscribe_to}::${value.timestamp}`
    }
}

//unsubscribe::timestamp::subscribe_to
class UnsubscribeMessageFormatter implements CryoMessageFormatter<CryoUnsubscribeMessage> {
    public Deserialize(value: string): CryoUnsubscribeMessage {
        const [type, unsubscribe_from, timestamp,] = value.split("::", 4);
        if (type !== "unsubscribe")
            throw new Error("Attempt to deserialize a non-unsubscribe message!");

        return {
            unsubscribe_from,
            timestamp: parseInt(timestamp),
            type: "unsubscribe"
        }
    }

    public Serialize(value: CryoUnsubscribeMessage): string {
        return `unsubscribe::${value.unsubscribe_from}::${value.timestamp}`
    }
}

//mktopic::timestamp::topic
class MakeTopicMessageFormatter implements CryoMessageFormatter<CryoMakeTopicMessage> {
    public Deserialize(value: string): CryoMakeTopicMessage {
        const [type, create_topic, timestamp] = value.split("::", 4);
        if (type !== "mktopic")
            throw new Error("Attempt to deserialize a non-mktopic message!");

        return {
            create_topic,
            timestamp: parseInt(timestamp),
            type: "mktopic"
        }
    }

    public Serialize(value: CryoMakeTopicMessage): string {
        return `mktopic::${value.create_topic}::${value.timestamp}`
    }
}

//rmtopic::timestamp::remove_topic
class RemoveTopicMessageFormatter implements CryoMessageFormatter<CryoRemoveTopicMessage> {
    public Deserialize(value: string): CryoRemoveTopicMessage {
        const [type, remove_topic, timestamp] = value.split("::", 4);
        if (type !== "rmtopic")
            throw new Error("Attempt to deserialize a non-rmtopic message!");

        return {
            remove_topic,
            timestamp: parseInt(timestamp),
            type: "rmtopic"
        }
    }

    public Serialize(value: CryoRemoveTopicMessage): string {
        return `rmtopic::${value.remove_topic}::${value.timestamp}`
    }
}

export default class CryoMessageFormatterFactory {
    public static GetFormatter(type: "data"): DataMessageFormatter;
    public static GetFormatter(type: "shutdown"): ShutdownMessageFormatter;
    public static GetFormatter(type: "error"): ErrorMessageFormatter;
    public static GetFormatter(type: "success"): SuccessMessageFormatter;
    public static GetFormatter(type: "subscribe"): SubscribeMessageFormatter;
    public static GetFormatter(type: "unsubscribe"): UnsubscribeMessageFormatter;
    public static GetFormatter(type: "mktopic"): MakeTopicMessageFormatter;
    public static GetFormatter(type: "rmtopic"): RemoveTopicMessageFormatter;
    public static GetFormatter(type: "data" | "shutdown" | "error" | "success" | "subscribe" | "unsubscribe" | "mktopic" | "rmtopic"): CryoMessageFormatter<any>;
    public static GetFormatter(type: string): CryoMessageFormatter<CryoAllMessage> {
        switch (type) {
            case "data":
                return new DataMessageFormatter();
            case "shutdown":
                return new ShutdownMessageFormatter();
            case "error":
                return new ErrorMessageFormatter();
            case "success":
                return new SuccessMessageFormatter();
            case "subscribe":
                return new SubscribeMessageFormatter();
            case "unsubscribe":
                return new UnsubscribeMessageFormatter();
            case "mktopic":
                return new MakeTopicMessageFormatter();
            case "rmtopic":
                return new RemoveTopicMessageFormatter();
            default:
                throw new Error(`Message format for type '${type}' is not supported!`)
        }
    }
}