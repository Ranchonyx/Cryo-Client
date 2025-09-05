import {createCipheriv, createDecipheriv} from "node:crypto";

export class CryoCryptoBox {
    private nonce = 0;

    public constructor(private readonly encrypt_key: Buffer, private readonly decryption_key: Buffer) {
    }

    private create_iv(): Buffer {
        const iv = Buffer.alloc(12);
        iv.writeUInt32BE(this.nonce++, 8);
        return iv;
    }

    public encrypt(plain: Buffer): Buffer {
        const iv = this.create_iv()
        const cipher = createCipheriv("aes-128-gcm", this.encrypt_key, iv);
        const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);
        const tag = cipher.getAuthTag();

        return Buffer.concat([iv, encrypted, tag]);
    }

    public decrypt(cipher: Buffer): Buffer {
        const iv = cipher.subarray(0, 12);
        const tag = cipher.subarray(cipher.byteLength - 16);
        const data = cipher.subarray(12, cipher.byteLength - 16);
        const decipher = createDecipheriv("aes-128-gcm", this.decryption_key, iv);
        decipher.setAuthTag(tag);

        return Buffer.concat([decipher.update(data), decipher.final()]);
    }
}