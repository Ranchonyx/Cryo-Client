export var BinaryMessageType;
(function (BinaryMessageType) {
    BinaryMessageType[BinaryMessageType["UTF8DATA"] = 0] = "UTF8DATA";
    BinaryMessageType[BinaryMessageType["ACK"] = 1] = "ACK";
    BinaryMessageType[BinaryMessageType["PING_PONG"] = 2] = "PING_PONG";
    BinaryMessageType[BinaryMessageType["ERROR"] = 3] = "ERROR";
    BinaryMessageType[BinaryMessageType["BINARYDATA"] = 4] = "BINARYDATA";
})(BinaryMessageType || (BinaryMessageType = {}));
class BufferUtil {
    static sidFromBuffer(buffer) {
        const uuidv4_p1 = buffer.subarray(0, 4).toString("hex");
        const uuidv4_p2 = buffer.subarray(4, 6).toString("hex");
        const uuidv4_p3 = buffer.subarray(6, 8).toString("hex");
        const uuidv4_p4 = buffer.subarray(8, 10).toString("hex");
        const uuidv4_p5 = buffer.subarray(10, 16).toString("hex");
        return [uuidv4_p1, uuidv4_p2, uuidv4_p3, uuidv4_p4, uuidv4_p5].join("-");
    }
    static sidToBuffer(sid) {
        return Buffer.from(sid.replaceAll("-", ""), 'hex');
    }
}
class AckMessageFormatter {
    Deserialize(value) {
        const sid = BufferUtil.sidFromBuffer(value);
        const ack = value.readUInt32BE(16);
        const type = value.readUint8(20);
        if (type !== BinaryMessageType.ACK)
            throw new Error("Attempt to deserialize a non-ack binary message!");
        return {
            sid,
            ack,
            type
        };
    }
    // noinspection JSUnusedLocalSymbols
    Serialize(sid, ack, payload = null) {
        const msg_buf = Buffer.alloc(16 + 4 + 1);
        const sid_buf = BufferUtil.sidToBuffer(sid);
        sid_buf.copy(msg_buf, 0);
        msg_buf.writeUInt32BE(ack, 16);
        msg_buf.writeUint8(BinaryMessageType.ACK, 20);
        return msg_buf;
    }
}
class PingPongMessageFormatter {
    Deserialize(value) {
        const sid = BufferUtil.sidFromBuffer(value);
        const ack = value.readUInt32BE(16);
        const type = value.readUint8(20);
        const payload = value.subarray(21).toString("utf8");
        if (type !== BinaryMessageType.PING_PONG)
            throw new Error("Attempt to deserialize a non-ping_pong binary message!");
        if (!(payload === "ping" || payload === "pong"))
            throw new Error(`Invalid payload ${payload} in ping_pong binary message!`);
        return {
            sid,
            ack,
            type,
            payload
        };
    }
    Serialize(sid, ack, payload) {
        const msg_buf = Buffer.alloc(16 + 4 + 1 + 4);
        const sid_buf = BufferUtil.sidToBuffer(sid);
        sid_buf.copy(msg_buf, 0);
        msg_buf.writeUInt32BE(ack, 16);
        msg_buf.writeUint8(BinaryMessageType.PING_PONG, 20);
        msg_buf.write(payload, 21);
        return msg_buf;
    }
}
class UTF8DataMessageFormatter {
    Deserialize(value) {
        const sid = BufferUtil.sidFromBuffer(value);
        const ack = value.readUInt32BE(16);
        const type = value.readUint8(20);
        const payload = value.subarray(21).toString("utf8");
        if (type !== BinaryMessageType.UTF8DATA)
            throw new Error("Attempt to deserialize a non-data binary message!");
        return {
            sid,
            ack,
            type,
            payload
        };
    }
    Serialize(sid, ack, payload) {
        const msg_buf = Buffer.alloc(16 + 4 + 1 + (payload?.length || 4));
        const sid_buf = BufferUtil.sidToBuffer(sid);
        sid_buf.copy(msg_buf, 0);
        msg_buf.writeUInt32BE(ack, 16);
        msg_buf.writeUint8(BinaryMessageType.UTF8DATA, 20);
        msg_buf.write(payload || "null", 21);
        return msg_buf;
    }
}
class BinaryDataMessageFormatter {
    Deserialize(value) {
        const sid = BufferUtil.sidFromBuffer(value);
        const ack = value.readUInt32BE(16);
        const type = value.readUint8(20);
        const payload = value.subarray(21);
        if (type !== BinaryMessageType.BINARYDATA)
            throw new Error("Attempt to deserialize a non-data binary message!");
        return {
            sid,
            ack,
            type,
            payload
        };
    }
    Serialize(sid, ack, payload) {
        const payload_length = payload ? payload.byteLength : 4;
        const msg_buf = Buffer.alloc(16 + 4 + 1 + payload_length);
        const sid_buf = BufferUtil.sidToBuffer(sid);
        sid_buf.copy(msg_buf, 0);
        msg_buf.writeUInt32BE(ack, 16);
        msg_buf.writeUint8(BinaryMessageType.BINARYDATA, 20);
        msg_buf.set(payload || Buffer.from("null", "utf-8"), 21);
        return msg_buf;
    }
}
class ErrorMessageFormatter {
    Deserialize(value) {
        const sid = BufferUtil.sidFromBuffer(value);
        const ack = value.readUInt32BE(16);
        const type = value.readUint8(20);
        const payload = value.subarray(21).toString("utf8");
        if (type !== BinaryMessageType.ERROR)
            throw new Error("Attempt to deserialize a non-error message!");
        return {
            sid,
            ack,
            type,
            payload
        };
    }
    Serialize(sid, ack, payload) {
        const msg_buf = Buffer.alloc(16 + 4 + 1 + (payload?.length || 13));
        const sid_buf = BufferUtil.sidToBuffer(sid);
        sid_buf.copy(msg_buf, 0);
        msg_buf.writeUInt32BE(ack, 16);
        msg_buf.writeUint8(BinaryMessageType.ERROR, 20);
        msg_buf.write(payload || "unknown_error", 21);
        return msg_buf;
    }
}
export default class CryoBinaryMessageFormatterFactory {
    static GetFormatter(type) {
        switch (type) {
            case "utf8data":
            case BinaryMessageType.UTF8DATA:
                return new UTF8DataMessageFormatter();
            case "error":
            case BinaryMessageType.ERROR:
                return new ErrorMessageFormatter();
            case "ack":
            case BinaryMessageType.ACK:
                return new AckMessageFormatter();
            case "ping_pong":
            case BinaryMessageType.PING_PONG:
                return new PingPongMessageFormatter();
            case "binarydata":
            case BinaryMessageType.BINARYDATA:
                return new BinaryDataMessageFormatter();
            default:
                throw new Error(`Binary message format for type '${type}' is not supported!`);
        }
    }
    static GetType(message) {
        const type = message.readUint8(20);
        if (type > BinaryMessageType.ERROR)
            throw new Error(`Unable to decode type from message ${message}. MAX_TYPE = 3, got ${type} !`);
        return type;
    }
    static GetAck(message) {
        return message.readUint32BE(16);
    }
    static GetSid(message) {
        return BufferUtil.sidFromBuffer(message);
    }
    static GetPayload(message, encoding = "utf8") {
        return message.subarray(21).toString(encoding);
    }
}
