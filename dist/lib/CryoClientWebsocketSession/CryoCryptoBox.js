import { createCipheriv, createDecipheriv } from "node:crypto";
export class CryoCryptoBox {
    encrypt_key;
    decryption_key;
    nonce = 0;
    constructor(encrypt_key, decryption_key) {
        this.encrypt_key = encrypt_key;
        this.decryption_key = decryption_key;
    }
    create_iv() {
        const iv = Buffer.alloc(12);
        iv.writeUInt32BE(this.nonce++, 8);
        return iv;
    }
    encrypt(plain) {
        const iv = this.create_iv();
        const cipher = createCipheriv("aes-128-gcm", this.encrypt_key, iv);
        const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
        const tag = cipher.getAuthTag();
        return Buffer.concat([iv, encrypted, tag]);
    }
    decrypt(cipher) {
        const iv = cipher.subarray(0, 12);
        const tag = cipher.subarray(cipher.byteLength - 16);
        const data = cipher.subarray(12, cipher.byteLength - 16);
        const decipher = createDecipheriv("aes-128-gcm", this.decryption_key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
}
