type PendingBinaryMessage = {
    timestamp: number;
    message: Buffer;
    payload?: string | Buffer;
}

export class AckTracker {
    private pending = new Map<number, PendingBinaryMessage>();

    public Track(ack: number, message: PendingBinaryMessage) {
        this.pending.set(ack, message);
    }

    public Confirm(ack: number): PendingBinaryMessage | null {
        const maybe_ack = this.pending.get(ack);
        if (!maybe_ack)
            return null;

        this.pending.delete(ack);
        return maybe_ack;
    }

    public Has(ack: number): boolean {
        return this.pending.has(ack);
    }
}