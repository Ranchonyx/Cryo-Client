import CryoFrameFormatter, { BinaryMessageType } from "../Common/CryoBinaryMessage/CryoFrameFormatter.js";
import { CreateDebugLogger } from "../Common/Util/CreateDebugLogger.js";
export class CryoFrameRouter {
    formatter;
    is_secure;
    decrypt;
    handlers;
    log;
    plaintext_during_handshake = [
        BinaryMessageType.SERVER_HELLO,
        BinaryMessageType.CLIENT_HELLO,
        BinaryMessageType.HANDSHAKE_DONE,
        BinaryMessageType.ACK, //Optional
        BinaryMessageType.PING_PONG, //Optional
        BinaryMessageType.ERROR
    ];
    constructor(formatter, is_secure, decrypt, handlers, log = CreateDebugLogger("CRYO_FRAME_ROUTER")) {
        this.formatter = formatter;
        this.is_secure = is_secure;
        this.decrypt = decrypt;
        this.handlers = handlers;
        this.log = log;
    }
    try_get_type(frame) {
        try {
            return CryoFrameFormatter.GetType(frame);
        }
        catch (e) {
            return null;
        }
        /*        if(!buf || buf.length < 21)
                    return null;

                const type_byte = buf.readUint8(20);
                return type_byte <= BinaryMessageType.HANDSHAKE_DONE ? type_byte as BinaryMessageType : null;*/
    }
    async do_route(raw) {
        let frame = raw;
        let type = this.try_get_type(raw);
        if (type === null && this.is_secure()) {
            try {
                frame = this.decrypt(raw);
                type = this.try_get_type(frame);
            }
            catch (e) {
                this.log(`Decryption failed: ${e}`, raw);
                return;
            }
        }
        if (type === null) {
            this.log(`Unknown frame type`, raw);
            return;
        }
        switch (type) {
            case BinaryMessageType.PING_PONG:
                await this.handlers.on_ping_pong(frame);
                return;
            case BinaryMessageType.ERROR:
                await this.handlers.on_error(frame);
                return;
            case BinaryMessageType.ACK:
                await this.handlers.on_ack(frame);
                return;
            case BinaryMessageType.UTF8DATA:
                await this.handlers.on_utf8(frame);
                return;
            case BinaryMessageType.BINARYDATA:
                await this.handlers.on_binary(frame);
                return;
            case BinaryMessageType.SERVER_HELLO:
                await this.handlers.on_server_hello?.(frame);
                return;
            case BinaryMessageType.CLIENT_HELLO:
                await this.handlers.on_client_hello?.(frame);
                return;
            case BinaryMessageType.HANDSHAKE_DONE:
                await this.handlers.on_handshake_done(frame);
                return;
            default:
                this.log(`Unsupported binary message type ${type}!`);
        }
    }
}
