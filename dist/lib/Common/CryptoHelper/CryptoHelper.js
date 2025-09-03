import { createCipheriv, createDecipheriv } from "node:crypto";
import { CreateDebugLogger } from "../Util/CreateDebugLogger.js";
export class PerSessionCryptoHelper {
    send_key;
    recv_key;
    log;
    nonce = 0;
    /*
        private nonce_rx = 0;
    */
    constructor(send_key, recv_key, log = CreateDebugLogger("CRYO_CRYPTO")) {
        this.send_key = send_key;
        this.recv_key = recv_key;
        this.log = log;
    }
    encrypt(plain) {
        this.log(`[ENCRYPT]\nlen=${plain.length}\nnonce=${this.nonce}\nfirst16=${plain.subarray(0, 16).toString("hex")}`);
        const iv = Buffer.alloc(12);
        iv.writeUInt32BE(this.nonce++, 8);
        const cipher = createCipheriv("aes-128-gcm", this.send_key, iv);
        const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
        const tag = cipher.getAuthTag();
        const out = Buffer.concat([iv, encrypted, tag]);
        this.log(`[ENCRYPT-OUT]\nlen=${out.length}\niv=${iv.toString("hex")}\ntag=${tag.toString("hex")}`);
        return out;
    }
    decrypt(cipher) {
        const iv = cipher.subarray(0, 12);
        const tag = cipher.subarray(cipher.byteLength - 16);
        const data = cipher.subarray(12, cipher.byteLength - 16);
        this.log(`[DECRYPT]\nlen=${cipher.length}\niv=${iv.toString("hex")}\ntag=${tag.toString("hex")}\ndata.length=${data.byteLength}`);
        const decipher = createDecipheriv("aes-128-gcm", this.recv_key, iv);
        decipher.setAuthTag(tag);
        const out = Buffer.concat([decipher.update(data), decipher.final()]);
        this.log(`[DECRYPT-OUT]\nlen=${out.length}\nfirst16=${out.subarray(0, 16).toString("hex")}`);
        return out;
    }
}
