import CryoFrameFormatter from "../CryoBinaryMessage/CryoFrameFormatter.js";
const typeToStringMap = {
    0: "ack",
    1: "error",
    2: "ping/pong",
    3: "utf8data",
    4: "binarydata",
    5: "server_hello",
    6: "client_hello",
    7: "handshake_done",
};
export class CryoFrameInspector {
    static Inspect(message, encoding = "utf8") {
        const sid = CryoFrameFormatter.GetSid(message);
        const ack = CryoFrameFormatter.GetAck(message);
        const type = CryoFrameFormatter.GetType(message);
        const type_str = typeToStringMap[type] || "unknown";
        const payload = CryoFrameFormatter.GetPayload(message, encoding);
        return `[${sid},${ack},${type_str},[${payload}]]`;
    }
}
