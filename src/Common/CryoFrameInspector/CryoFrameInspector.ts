import CryoFrameFormatter from "../CryoBinaryMessage/CryoFrameFormatter.js";

const typeToStringMap = {
    0: "utf8data",
    1: "ack",
    2: "ping/pong",
    3: "error",
    4: "binarydata",
    5: "kexchg"
}

export class CryoFrameInspector {
    public static Inspect(message: Buffer, encoding: BufferEncoding = "utf8"): string {
        const sid = CryoFrameFormatter.GetSid(message);
        const ack = CryoFrameFormatter.GetAck(message);
        const type = CryoFrameFormatter.GetType(message);
        const type_str = typeToStringMap[type] || "unknown";

        const payload = CryoFrameFormatter.GetPayload(message, encoding);

        return `[${sid},${ack},${type_str},[${payload}]]`
    }
}