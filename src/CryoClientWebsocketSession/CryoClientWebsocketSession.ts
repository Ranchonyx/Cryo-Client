import {ICryoClientWebsocketSessionEvents, PendingBinaryMessage} from "./types/CryoClientWebsocketSession.js";
import EventEmitter from "node:events";
import {AckTracker} from "../Common/AckTracker/AckTracker.js";
import CryoFrameFormatter, {BinaryMessageType} from "../Common/CryoBinaryMessage/CryoFrameFormatter.js";
import {CryoFrameInspector} from "../Common/CryoFrameInspector/CryoFrameInspector.js";
import {createECDH, createHash, ECDH, randomUUID, UUID} from "node:crypto";
import {DebugLoggerFunction} from "node:util";
import {CreateDebugLogger} from "../Common/Util/CreateDebugLogger.js";
import WebSocket from "ws";
import {PerSessionCryptoHelper} from "../Common/CryptoHelper/CryptoHelper.js";

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

    private readonly ecdh: ECDH = createECDH("prime256v1");
    private recv_key: Buffer | null = null;
    private send_key: Buffer | null = null;
    private l_crypto_ack: number | null = null;
    private l_crypto: PerSessionCryptoHelper | null = null;


    private constructor(private host: string, private sid: UUID, private socket: WebSocket, private timeout: number, private bearer: string, private log: DebugLoggerFunction = CreateDebugLogger("CRYO_CLIENT_SESSION")) {
        super();
        this.AttachListenersToSocket(socket);
        this.ecdh.generateKeys();
    }

    private AttachListenersToSocket(socket: WebSocket) {
        socket.on("message", this.HandleIncomingBinaryMessage.bind(this));

        setImmediate(() => this.emit("connected"));

        /*
                socket.on("message", this.HandleIncomingBinaryMessage.bind(this));
        */
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
    private HandleOutgoingBinaryMessage(ougoing_message: Buffer): void {
        //Create a pending message with a new ack number and queue it for acknowledgement by the server
        const message_ack = CryoFrameFormatter.GetAck(ougoing_message);
        this.server_ack_tracker.Track(message_ack, {
            timestamp: Date.now(),
            message: ougoing_message
        });

        //Send the message buffer to the server
        if (!this.socket)
            return;

        const message = this.secure ? this.l_crypto!.encrypt(ougoing_message) : ougoing_message;
        this.socket.send(message, (maybe_error) => {
            if (maybe_error)
                this.HandleError(maybe_error);
        });

        this.log(`Sent ${CryoFrameInspector.Inspect(ougoing_message)} to server.`);
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

        if(this.l_crypto_ack && ack_id === this.l_crypto_ack) {
            this.l_crypto = new PerSessionCryptoHelper(this.send_key!, this.recv_key!);
            this.l_crypto_ack = null;
            this.log("Got KEX Ack, enabling encryption.")
        }

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

    private async HandleKeyExchangeMessage(message: Buffer): Promise<void> {
        const decoded = CryoFrameFormatter
            .GetFormatter("kexchg")
            .Deserialize(message);
        const server_pub_key = decoded.payload;

        //Basic key checks
        if(server_pub_key.length !== 65 ||server_pub_key[0] !== 0x04) {
            throw new Error(`Invalid server public key. Got ${server_pub_key.byteLength} bytes.`)
        }

        //Derive keys
        const secret = this.ecdh.computeSecret(server_pub_key);
        const hash = createHash("sha256")
            .update(secret)
            .digest();

        //We sent with second half, receive with first half (opposite of server)
        this.recv_key = hash.subarray(0, 16);
        this.send_key = hash.subarray(16, 32);

        //Ack the server's KEX without being encrypted yet
        const encodedAckMessage = this.ack_formatter
            .Serialize(this.sid, decoded.ack);

        //Send our KEX with our public key
        const client_pub_key = this.ecdh.getPublicKey(null, "uncompressed");
        this.current_ack++;
        const my_kex_ack_id = this.current_ack++;
        const client_kex = CryoFrameFormatter
            .GetFormatter("kexchg")
            .Serialize(this.sid, my_kex_ack_id, client_pub_key);

        this.l_crypto_ack = my_kex_ack_id;
        this.HandleOutgoingBinaryMessage(client_kex);
        this.log("Client sent KEX, waiting for server ACK before enabling encryption.");
    }

    /*
    * Handle incoming binary messages
    * */
    private async HandleIncomingBinaryMessage(incoming_message: Buffer): Promise<void> {
        const message = this.secure ? this.l_crypto!.decrypt(incoming_message) : incoming_message;
        const message_type = CryoFrameFormatter.GetType(message);
        this.log(`Received ${CryoFrameInspector.Inspect(message)} from server.`);

        switch (message_type) {
            case BinaryMessageType.PING_PONG:
                await this.HandlePingPongMessage(message);
                return;
            case BinaryMessageType.ERROR:
                await this.HandleErrorMessage(message);
                return;
            case BinaryMessageType.ACK:
                await this.HandleAckMessage(message);
                return;
            case BinaryMessageType.UTF8DATA:
                await this.HandleUTF8DataMessage(message);
                return;
            case BinaryMessageType.BINARYDATA:
                await this.HandleBinaryDataMessage(message);
                return;
            case BinaryMessageType.KEXCHG:
                await this.HandleKeyExchangeMessage(message);
                return;
            default:
                throw new Error(`Handle binary message type ${message_type}!`);
        }
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
        return this.l_crypto !== null;
    }

    public get session_id(): UUID {
        return this.sid;
    }

    public Destroy() {
        this.socket.close();
    }
}