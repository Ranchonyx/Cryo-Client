import CryoFrameFormatter, {BinaryMessageType} from "../Common/CryoBinaryMessage/CryoFrameFormatter.js";
import {DebugLoggerFunction} from "node:util";
import {CreateDebugLogger} from "../Common/Util/CreateDebugLogger.js";

interface RouterHandlers {
    //Normal frame routing
    on_ping_pong: (frame: Buffer) => Promise<void>;
    on_ack: (frame: Buffer) => Promise<void>;
    on_error: (frame: Buffer) => Promise<void>;
    on_utf8: (frame: Buffer) => Promise<void>;
    on_binary: (frame: Buffer) => Promise<void>;

    //Handshake frame routing should go to the HandshakeEngine
    on_server_hello?: (frame: Buffer) => Promise<void>;
    on_client_hello?: (frame: Buffer) => Promise<void>;
    on_handshake_done: (frame: Buffer) => Promise<void>;
}

export class CryoFrameRouter {
    private plaintext_during_handshake: BinaryMessageType[] = [
        BinaryMessageType.SERVER_HELLO,
        BinaryMessageType.CLIENT_HELLO,
        BinaryMessageType.HANDSHAKE_DONE,
        BinaryMessageType.ACK,              //Optional
        BinaryMessageType.PING_PONG,        //Optional
        BinaryMessageType.ERROR
    ];

    public constructor(
        private readonly formatter: typeof CryoFrameFormatter,
        private readonly is_secure: () => boolean,
        private readonly decrypt: (buffer: Buffer) => Buffer,
        private readonly handlers: RouterHandlers,
        private log: DebugLoggerFunction = CreateDebugLogger("CRYO_FRAME_ROUTER")
    ) {}

    private try_get_type(buf: Buffer): BinaryMessageType | null {
        if(!buf || buf.length < 21)
            return null;

        const type_byte = buf.readUint8(20);
        return type_byte <= BinaryMessageType.HANDSHAKE_DONE ? type_byte as BinaryMessageType : null;
    }

    public async do_route(raw: Buffer): Promise<void> {
        let frame: Buffer = raw;
        let type: BinaryMessageType | null = null;

        type = this.try_get_type(raw);
        if(type === null && this.is_secure()) {
            try {
                const decrypted = this.decrypt(raw);
                frame = decrypted;

                type = this.try_get_type(frame);
            } catch (e) {
                this.log(`Decryption failed: ${e}`, raw);
                return;
            }
        }

        if(type === null) {
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