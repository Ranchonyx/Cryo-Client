import CryoBinaryMessageFormatterFactory from "../CryoBinaryMessage/CryoBinaryMessageFormatterFactory.js";
const typeToStringMap = {
    0: "utf8data",
    1: "ack",
    2: "ping/pong",
    3: "error",
    4: "binarydata"
};
export class CryoFrameInspector {
    static Inspect(message, encoding = "utf8") {
        const sid = CryoBinaryMessageFormatterFactory.GetSid(message);
        const ack = CryoBinaryMessageFormatterFactory.GetAck(message);
        const type = CryoBinaryMessageFormatterFactory.GetType(message);
        const type_str = typeToStringMap[type] || "unknown";
        const payload = CryoBinaryMessageFormatterFactory.GetPayload(message, encoding);
        return `[${sid},${ack},${type_str},[${payload}]]`;
    }
}
