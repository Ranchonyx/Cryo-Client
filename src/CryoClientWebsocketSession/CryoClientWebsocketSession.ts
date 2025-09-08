import {ICryoClientWebsocketSessionEvents, PendingBinaryMessage} from "./types/CryoClientWebsocketSession.js";
import EventEmitter from "node:events";
import {AckTracker} from "../Common/AckTracker/AckTracker.js";
import CryoFrameFormatter, {BinaryMessageType} from "../Common/CryoBinaryMessage/CryoFrameFormatter.js";
import {CryoFrameInspector} from "../Common/CryoFrameInspector/CryoFrameInspector.js";
import {randomUUID, UUID} from "node:crypto";
import {DebugLoggerFunction} from "node:util";
import {CreateDebugLogger} from "../Common/Util/CreateDebugLogger.js";
import WebSocket from "ws";
import {CryoCryptoBox} from "./CryoCryptoBox.js";
import {CryoHandshakeEngine, HandshakeEvents} from "./CryoHandshakeEngine.js";
import {CryoFrameRouter} from "./CryoFrameRouter.js";

export interface CryoClientWebsocketSession {
    on<U extends keyof ICryoClientWebsocketSessionEvents>(event: U, listener: ICryoClientWebsocketSessionEvents[U]): this;

    emit<U extends keyof ICryoClientWebsocketSessionEvents>(event: U, ...args: Parameters<ICryoClientWebsocketSessionEvents[U]>): boolean;
}

/*
* Cryo Websocket session layer. Handles Binary formatting and ACKs and whatnot
* */
export class CryoClientWebsocketSession extends EventEmitter implements CryoClientWebsocketSession {
    private messages_pending_server_ack = new Map<number, PendingBinaryMessage>();
    private server_ack_tracker: AckTracker = new AckTracker();
    private current_ack = 0;

    private readonly ping_pong_formatter = CryoFrameFormatter.GetFormatter("ping_pong");
    private readonly ack_formatter = CryoFrameFormatter.GetFormatter("ack");
    private readonly error_formatter = CryoFrameFormatter.GetFormatter("error");
    private readonly utf8_formatter = CryoFrameFormatter.GetFormatter("utf8data");
    private readonly binary_formatter = CryoFrameFormatter.GetFormatter("binarydata");

    private crypto: CryoCryptoBox | null = null;
    private handshake: CryoHandshakeEngine;
    private router: CryoFrameRouter;

    private constructor(private host: string, private sid: UUID, private socket: WebSocket, private timeout: number, private bearer: string, private log: DebugLoggerFunction = CreateDebugLogger("CRYO_CLIENT_SESSION")) {
        super();
        const handshake_events: HandshakeEvents = {
            onSecure: ({transmit_key, receive_key}) => {
                this.crypto = new CryoCryptoBox(transmit_key, receive_key);
                this.log("Channel secured.");
                this.emit("connected"); // only emit once we’re secure
            },
            onFailure: (reason: string) => {
                this.log(`Handshake failure: ${reason}`);
                this.Destroy();
            }
        };


        this.handshake = new CryoHandshakeEngine(
            this.sid,
            async (buf) => this.socket.send(buf), // raw plaintext send
            CryoFrameFormatter,
            () => this.current_ack++,
            handshake_events,
        );

        this.router = new CryoFrameRouter(
            CryoFrameFormatter,
            () => this.handshake.is_secure,
            (b) => this.crypto!.decrypt(b),
            {
                on_ping_pong: async (b) => this.HandlePingPongMessage(b),
                on_ack: async (b) => this.HandleAckMessage(b),
                on_error: async (b) => this.HandleErrorMessage(b),
                on_utf8: async (b) => this.HandleUTF8DataMessage(b),
                on_binary: async (b) => this.HandleBinaryDataMessage(b),

                on_server_hello: async (b) => this.handshake.on_server_hello(b),
                on_handshake_done: async (b) => this.handshake.on_server_handshake_done(b)
            }
        );

        this.AttachListenersToSocket(socket);
    }

    private AttachListenersToSocket(socket: WebSocket) {
        socket.on("message", async (raw: Buffer) => {
            await this.router.do_route(raw);
        });

        socket.on("error", this.HandleError.bind(this));
        socket.on("close", this.HandleClose.bind(this));
    }

    private static async ConstructSocket(host: string, timeout: number, bearer: string, sid: string): Promise<WebSocket> {
        const full_host_url = new URL(host);
        full_host_url.searchParams.set("authorization", `Bearer ${bearer}`);
        full_host_url.searchParams.set("x-cryo-sid", sid);

        const sck = new WebSocket(full_host_url);

        return new Promise<WebSocket>((resolve, reject) => {
            setTimeout(() => {
                if (sck.readyState !== WebSocket.OPEN)
                    reject(new Error(`Connection timeout of ${timeout} ms reached!`));
            }, timeout)
            sck.addEventListener("open", () => {
                sck.removeAllListeners("error");
                resolve(sck);
            })
            sck.addEventListener("error", (err) => {
                reject(new Error(`Error during session initialisation!`, {cause: err}));
            });
        })
    }

    public static async Connect(host: string, bearer: string, timeout: number = 5000): Promise<CryoClientWebsocketSession> {
        const sid = randomUUID();

        const socket = await CryoClientWebsocketSession.ConstructSocket(host, timeout, bearer, sid);
        return new CryoClientWebsocketSession(host, sid, socket, timeout, bearer);
    }

    /*
    * Handle an outgoing binary message
    * */
    private HandleOutgoingBinaryMessage(outgoing_message: Buffer): void {
        //Create a pending message with a new ack number and queue it for acknowledgement by the server
        const type = CryoFrameFormatter.GetType(outgoing_message);
        if (type === BinaryMessageType.UTF8DATA || type === BinaryMessageType.BINARYDATA) {
            const message_ack = CryoFrameFormatter.GetAck(outgoing_message);
            this.server_ack_tracker.Track(message_ack, {
                timestamp: Date.now(),
                message: outgoing_message
            });
        }

        //Send the message buffer to the server
        if (!this.socket)
            return;

        const message = this.secure ? this.crypto!.encrypt(outgoing_message) : outgoing_message;
        this.socket.send(message, (maybe_error) => {
            if (maybe_error)
                this.HandleError(maybe_error);
        });

        this.log(`Sent ${CryoFrameInspector.Inspect(outgoing_message)} to server.`);
    }

    /*
    * Respond to PONG frames with PING and vice versa
    * */
    private async HandlePingPongMessage(message: Buffer): Promise<void> {
        const decodedPingPongMessage = this.ping_pong_formatter
            .Deserialize(message);

        const ping_pongMessage = this.ping_pong_formatter
            .Serialize(this.sid, decodedPingPongMessage.ack, decodedPingPongMessage.payload === "pong" ? "ping" : "pong");

        this.HandleOutgoingBinaryMessage(ping_pongMessage);
    }

    /*
    * Handling of binary error messages from the server, currently just log it
    * */
    private async HandleErrorMessage(message: Buffer): Promise<void> {
        const decodedErrorMessage = this.error_formatter
            .Deserialize(message);

        this.log(decodedErrorMessage.payload);
    }

    /*
    * Locally ACK the pending message if it matches the server's ACK
    * */
    private async HandleAckMessage(message: Buffer): Promise<void> {
        const decodedAckMessage = this.ack_formatter
            .Deserialize(message);
        const ack_id = decodedAckMessage.ack;

        const found_message = this.server_ack_tracker.Confirm(ack_id);

        if (!found_message) {
            this.log(`Got unknown ack_id ${ack_id} from server.`);
            return;
        }

        this.messages_pending_server_ack.delete(ack_id);
        this.log(`Got ACK ${ack_id} from server.`);
    }

    /*
    * Extract payload from the binary message and emit the message event with the utf8 payload
    * */
    private async HandleUTF8DataMessage(message: Buffer): Promise<void> {
        const decodedDataMessage = this.utf8_formatter
            .Deserialize(message);

        const payload = decodedDataMessage.payload;

        const encodedAckMessage = this.ack_formatter
            .Serialize(this.sid, decodedDataMessage.ack);

        this.HandleOutgoingBinaryMessage(encodedAckMessage);
        this.emit("message-utf8", payload);
    }

    /*
    * Extract payload from the binary message and emit the message event with the utf8 payload
    * */
    private async HandleBinaryDataMessage(message: Buffer): Promise<void> {
        const decodedDataMessage = this.binary_formatter
            .Deserialize(message);

        const payload = decodedDataMessage.payload;

        const encodedAckMessage = this.ack_formatter
            .Serialize(this.sid, decodedDataMessage.ack);

        this.HandleOutgoingBinaryMessage(encodedAckMessage);
        this.emit("message-binary", payload);
    }

    private async HandleError(err: Error) {
        this.log(`${err.name} Exception in CryoSocket: ${err.message}`);
        this.socket.close(1000, `CryoSocket ${this.sid} was closed due to an error.`);
    }

    private TranslateCloseCode(code: number): string {
        switch (code) {
            case 1000:
                return "Connection closed normally.";
            case 1006:
                return "Connection closed abnormally."
            default:
                return "Unspecified cause for connection closure."
        }
    }

    private async HandleClose(code: number, reason: Buffer) {
        this.log(`CryoSocket was closed, code '${code}' (${this.TranslateCloseCode(code)}), reason '${reason.toString("utf8")}' .`);

        if (code !== 1000) {
            let current_attempt = 0;
            //If the connection was not normally closed, try to reconnect
            this.log(`Abnormal termination of Websocket connection, attempting to reconnect...`);
            ///@ts-expect-error
            this.socket = null;

            this.emit("disconnected")
            while (current_attempt < 5) {
                try {
                    this.socket = await CryoClientWebsocketSession.ConstructSocket(this.host, this.timeout, this.bearer, this.sid);
                    this.AttachListenersToSocket(this.socket);

                    this.emit("reconnected");
                    return;
                } catch (ex) {
                    if (ex instanceof Error) {
                        ///@ts-expect-error
                        const errorCode = ex.cause?.error?.code as string;
                        console.warn(`Unable to reconnect to '${this.host}'. Error code: '${errorCode}'. Retry attempt ${++current_attempt} / 5 ...`);
                        await new Promise((resolve) => setTimeout(resolve, 5000));
                    }
                }
            }

            console.warn(`Gave up on reconnecting to '${this.host}'`)
            return;
        }

        if (this.socket)
            this.socket.terminate();

        this.emit("closed", code, reason.toString("utf8"));
    }

    /*
    * Send an utf8 message to the server
    * */
    public SendUTF8(message: string): void {
        const new_ack_id = this.current_ack++;

        const formatted_message = CryoFrameFormatter
            .GetFormatter("utf8data")
            .Serialize(this.sid, new_ack_id, message);

        this.HandleOutgoingBinaryMessage(formatted_message);
    }

    /*
    * Send a binary message to the server
    * */
    public SendBinary(message: Buffer): void {
        const new_ack_id = this.current_ack++;

        const formatted_message = CryoFrameFormatter
            .GetFormatter("binarydata")
            .Serialize(this.sid, new_ack_id, message);

        this.HandleOutgoingBinaryMessage(formatted_message);
    }

    public get secure(): boolean {
        return this.crypto !== null;
    }

    public get session_id(): UUID {
        return this.sid;
    }

    public Destroy() {
        this.socket.close();
    }
}