import EventEmitter from "node:events";
import { AckTracker } from "../Common/AckTracker/AckTracker.js";
import CryoFrameFormatter, { BinaryMessageType } from "../Common/CryoBinaryMessage/CryoFrameFormatter.js";
import { CryoFrameInspector } from "../Common/CryoFrameInspector/CryoFrameInspector.js";
import { createECDH, createHash, randomUUID } from "node:crypto";
import { CreateDebugLogger } from "../Common/Util/CreateDebugLogger.js";
import WebSocket from "ws";
import { PerSessionCryptoHelper } from "../Common/CryptoHelper/CryptoHelper.js";
/*
* Cryo Websocket session layer. Handles Binary formatting and ACKs and whatnot
* */
export class CryoClientWebsocketSession extends EventEmitter {
    host;
    sid;
    socket;
    timeout;
    bearer;
    log;
    messages_pending_server_ack = new Map();
    server_ack_tracker = new AckTracker();
    current_ack = 0;
    ping_pong_formatter = CryoFrameFormatter.GetFormatter("ping_pong");
    ack_formatter = CryoFrameFormatter.GetFormatter("ack");
    error_formatter = CryoFrameFormatter.GetFormatter("error");
    utf8_formatter = CryoFrameFormatter.GetFormatter("utf8data");
    binary_formatter = CryoFrameFormatter.GetFormatter("binarydata");
    ecdh = createECDH("prime256v1");
    l_crypto = null;
    constructor(host, sid, socket, timeout, bearer, log = CreateDebugLogger("CRYO_CLIENT_SESSION")) {
        super();
        this.host = host;
        this.sid = sid;
        this.socket = socket;
        this.timeout = timeout;
        this.bearer = bearer;
        this.log = log;
        this.AttachListenersToSocket(socket);
    }
    AttachListenersToSocket(socket) {
        socket.on("message", this.HandleIncomingBinaryMessage.bind(this));
        setImmediate(() => this.emit("connected"));
        /*
                socket.on("message", this.HandleIncomingBinaryMessage.bind(this));
        */
        socket.on("error", this.HandleError.bind(this));
        socket.on("close", this.HandleClose.bind(this));
    }
    static async ConstructSocket(host, timeout, bearer, sid) {
        const full_host_url = new URL(host);
        full_host_url.searchParams.set("authorization", `Bearer ${bearer}`);
        full_host_url.searchParams.set("x-cryo-sid", sid);
        const sck = new WebSocket(full_host_url);
        return new Promise((resolve, reject) => {
            setTimeout(() => {
                if (sck.readyState !== WebSocket.OPEN)
                    reject(new Error(`Connection timeout of ${timeout} ms reached!`));
            }, timeout);
            sck.addEventListener("open", () => {
                sck.removeAllListeners("error");
                resolve(sck);
            });
            sck.addEventListener("error", (err) => {
                reject(new Error(`Error during session initialisation!`, { cause: err }));
            });
        });
    }
    static async Connect(host, bearer, timeout = 5000) {
        const sid = randomUUID();
        const socket = await CryoClientWebsocketSession.ConstructSocket(host, timeout, bearer, sid);
        return new CryoClientWebsocketSession(host, sid, socket, timeout, bearer);
    }
    /*
    * Handle an outgoing binary message
    * */
    HandleOutgoingBinaryMessage(ougoing_message) {
        //Create a pending message with a new ack number and queue it for acknowledgement by the server
        const message_ack = CryoFrameFormatter.GetAck(ougoing_message);
        this.server_ack_tracker.Track(message_ack, {
            timestamp: Date.now(),
            message: ougoing_message
        });
        //Send the message buffer to the server
        if (!this.socket)
            return;
        const message = this.secure ? this.l_crypto.encrypt(ougoing_message) : ougoing_message;
        this.socket.send(message, (maybe_error) => {
            if (maybe_error)
                this.HandleError(maybe_error);
        });
        this.log(`Sent ${CryoFrameInspector.Inspect(message)} to server.`);
    }
    /*
    * Respond to PONG frames with PING and vice versa
    * */
    async HandlePingPongMessage(message) {
        const decodedPingPongMessage = this.ping_pong_formatter
            .Deserialize(message);
        const ping_pongMessage = this.ping_pong_formatter
            .Serialize(this.sid, decodedPingPongMessage.ack, decodedPingPongMessage.payload === "pong" ? "ping" : "pong");
        this.HandleOutgoingBinaryMessage(ping_pongMessage);
    }
    /*
    * Handling of binary error messages from the server, currently just log it
    * */
    async HandleErrorMessage(message) {
        const decodedErrorMessage = this.error_formatter
            .Deserialize(message);
        this.log(decodedErrorMessage.payload);
    }
    /*
    * Locally ACK the pending message if it matches the server's ACK
    * */
    async HandleAckMessage(message) {
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
    async HandleUTF8DataMessage(message) {
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
    async HandleBinaryDataMessage(message) {
        const decodedDataMessage = this.binary_formatter
            .Deserialize(message);
        const payload = decodedDataMessage.payload;
        const encodedAckMessage = this.ack_formatter
            .Serialize(this.sid, decodedDataMessage.ack);
        this.HandleOutgoingBinaryMessage(encodedAckMessage);
        this.emit("message-binary", payload);
    }
    async HandleKeyExchangeMessage(message) {
        const decoded = CryoFrameFormatter
            .GetFormatter("kexchg")
            .Deserialize(message);
        const server_pub_key = decoded.payload;
        const secret = this.ecdh.computeSecret(server_pub_key);
        //Make two aes128 hashes from the secret
        const hash = createHash("sha256")
            .update(secret)
            .digest();
        const send_key = hash.subarray(0, 16);
        const recv_key = hash.subarray(16, 32);
        this.l_crypto = new PerSessionCryptoHelper(send_key, recv_key);
        const encodedAckMessage = this.ack_formatter
            .Serialize(this.sid, decoded.ack);
        this.HandleOutgoingBinaryMessage(encodedAckMessage);
        this.log("Derived session keys, encryption now enabled.");
    }
    /*
    * Handle incoming binary messages
    * */
    async HandleIncomingBinaryMessage(incoming_message) {
        const message = this.secure ? this.l_crypto.decrypt(incoming_message) : incoming_message;
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
    async HandleError(err) {
        this.log(`${err.name} Exception in CryoSocket: ${err.message}`);
        this.socket.close(1000, `CryoSocket ${this.sid} was closed due to an error.`);
    }
    TranslateCloseCode(code) {
        switch (code) {
            case 1000:
                return "Connection closed normally.";
            case 1006:
                return "Connection closed abnormally.";
            default:
                return "Unspecified cause for connection closure.";
        }
    }
    async HandleClose(code, reason) {
        this.log(`CryoSocket was closed, code '${code}' (${this.TranslateCloseCode(code)}), reason '${reason.toString("utf8")}' .`);
        if (code !== 1000) {
            let current_attempt = 0;
            //If the connection was not normally closed, try to reconnect
            this.log(`Abnormal termination of Websocket connection, attempting to reconnect...`);
            ///@ts-expect-error
            this.socket = null;
            this.emit("disconnected");
            while (current_attempt < 5) {
                try {
                    this.socket = await CryoClientWebsocketSession.ConstructSocket(this.host, this.timeout, this.bearer, this.sid);
                    this.AttachListenersToSocket(this.socket);
                    this.emit("reconnected");
                    return;
                }
                catch (ex) {
                    if (ex instanceof Error) {
                        ///@ts-expect-error
                        const errorCode = ex.cause?.error?.code;
                        console.warn(`Unable to reconnect to '${this.host}'. Error code: '${errorCode}'. Retry attempt ${++current_attempt} / 5 ...`);
                        await new Promise((resolve) => setTimeout(resolve, 5000));
                    }
                }
            }
            console.warn(`Gave up on reconnecting to '${this.host}'`);
            return;
        }
        if (this.socket)
            this.socket.terminate();
        this.emit("closed", code, reason.toString("utf8"));
    }
    /*
    * Send an utf8 message to the server
    * */
    SendUTF8(message) {
        const new_ack_id = this.current_ack++;
        const formatted_message = CryoFrameFormatter
            .GetFormatter("utf8data")
            .Serialize(this.sid, new_ack_id, message);
        this.HandleOutgoingBinaryMessage(formatted_message);
    }
    /*
    * Send a binary message to the server
    * */
    SendBinary(message) {
        const new_ack_id = this.current_ack++;
        const formatted_message = CryoFrameFormatter
            .GetFormatter("binarydata")
            .Serialize(this.sid, new_ack_id, message);
        this.HandleOutgoingBinaryMessage(formatted_message);
    }
    get secure() {
        return this.l_crypto !== null;
    }
    get session_id() {
        return this.sid;
    }
    Destroy() {
        this.socket.close();
    }
}
