//data::topic::timestamp::contents
class DataMessageFormatter {
    Deserialize(value) {
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
            };
        }
        catch (ex) {
            throw new Error("Invalid JSON data in message body!");
        }
    }
    Serialize(value) {
        return `data::${value.topic}::${JSON.stringify(value.data)}::${value.timestamp}`;
    }
}
//shutdown::topic::timestamp::reason
class ShutdownMessageFormatter {
    Deserialize(value) {
        const [type, topic, reason, timestamp] = value.split("::", 4);
        if (type !== "shutdown")
            throw new Error("Attempt to deserialize a non-shutdown message!");
        return {
            topic,
            reason,
            timestamp: parseInt(timestamp),
            type: "shutdown"
        };
    }
    Serialize(value) {
        return `shutdown::${value.topic}::${value.reason}::${value.timestamp}`;
    }
}
//error::timestamp::message
class ErrorMessageFormatter {
    Deserialize(value) {
        const [type, message, timestamp] = value.split("::", 4);
        if (type !== "error")
            throw new Error("Attempt to deserialize a non-error message!");
        return {
            message,
            timestamp: parseInt(timestamp),
            type: "error"
        };
    }
    Serialize(value) {
        return `error::${value.message}::${value.timestamp}`;
    }
}
//success::timestamp::message
class SuccessMessageFormatter {
    Deserialize(value) {
        const [type, message, timestamp] = value.split("::", 4);
        if (type !== "success")
            throw new Error("Attempt to deserialize a non-success message!");
        return {
            message,
            timestamp: parseInt(timestamp),
            type: "success"
        };
    }
    Serialize(value) {
        return `success::${value.message}::${value.timestamp}`;
    }
}
//subscribe::timestamp::subscribe_to
class SubscribeMessageFormatter {
    Deserialize(value) {
        const [type, subscribe_to, timestamp] = value.split("::", 4);
        if (type !== "subscribe")
            throw new Error("Attempt to deserialize a non-subscribe message!");
        return {
            subscribe_to,
            timestamp: parseInt(timestamp),
            type: "subscribe"
        };
    }
    Serialize(value) {
        return `subscribe::${value.subscribe_to}::${value.timestamp}`;
    }
}
//unsubscribe::timestamp::subscribe_to
class UnsubscribeMessageFormatter {
    Deserialize(value) {
        const [type, unsubscribe_from, timestamp,] = value.split("::", 4);
        if (type !== "unsubscribe")
            throw new Error("Attempt to deserialize a non-unsubscribe message!");
        return {
            unsubscribe_from,
            timestamp: parseInt(timestamp),
            type: "unsubscribe"
        };
    }
    Serialize(value) {
        return `unsubscribe::${value.unsubscribe_from}::${value.timestamp}`;
    }
}
//mktopic::timestamp::topic
class MakeTopicMessageFormatter {
    Deserialize(value) {
        const [type, create_topic, timestamp] = value.split("::", 4);
        if (type !== "mktopic")
            throw new Error("Attempt to deserialize a non-mktopic message!");
        return {
            create_topic,
            timestamp: parseInt(timestamp),
            type: "mktopic"
        };
    }
    Serialize(value) {
        return `mktopic::${value.create_topic}::${value.timestamp}`;
    }
}
//rmtopic::timestamp::remove_topic
class RemoveTopicMessageFormatter {
    Deserialize(value) {
        const [type, remove_topic, timestamp] = value.split("::", 4);
        if (type !== "rmtopic")
            throw new Error("Attempt to deserialize a non-rmtopic message!");
        return {
            remove_topic,
            timestamp: parseInt(timestamp),
            type: "rmtopic"
        };
    }
    Serialize(value) {
        return `rmtopic::${value.remove_topic}::${value.timestamp}`;
    }
}
export default class CryoMessageFormatterFactory {
    static GetFormatter(type) {
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
                throw new Error(`Message format for type '${type}' is not supported!`);
        }
    }
}
