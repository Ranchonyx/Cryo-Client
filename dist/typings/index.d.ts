import {EventEmitter} from "node:events";

export interface ICryoClientWebsocketSessionEvents {
    "message-utf8": (message: string) => void;
    "message-binary": (message: Buffer) => void;
    "closed": (code: number, reason: string) => void;
    "connected": () => void;
    "disconnected": () => void;
    "reconnected": () => void;
}

export interface CryoClientWebsocketSession {
    on<U extends keyof ICryoClientWebsocketSessionEvents>(event: U, listener: ICryoClientWebsocketSessionEvents[U]): this;

    emit<U extends keyof ICryoClientWebsocketSessionEvents>(event: U, ...args: Parameters<ICryoClientWebsocketSessionEvents[U]>): boolean;
}

export declare class CryoClientWebsocketSession extends EventEmitter implements CryoClientWebsocketSession {
    public SendUTF8(message: string): void;

    public SendBinary(message: Buffer): void;

    public Destroy(): void;
}

/**
 * Create a Cryo client
 * @param host - The server to connect to
 * @param bearer - The Bearer token for the server to validate
 * @param use_cale - If cALE (application layer encryption) should be enabled
 * @param timeout - How long to wait until the client stops establishing a connection
 * */
export declare function cryo(host: string, bearer: string, use_cale: boolean, timeout?: number): Promise<CryoClientWebsocketSession>;