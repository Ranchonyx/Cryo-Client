export interface ICryoClientWebsocketSessionEvents {
    "message-utf8": (message: string) => void;
    "message-binary": (message: Buffer) => void;
    "closed": (code: number, reason: string) => void;
    "connected": () => void;
    "disconnected": () => void;
    "reconnected": () => void;

}

export type PendingBinaryMessage = {
    timestamp: number;
    message: Buffer;
    payload?: string | Buffer;
}

export type PendingUTF8Message = {
    timestamp: number;
    message: string;
}