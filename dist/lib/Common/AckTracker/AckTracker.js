export class AckTracker {
    pending = new Map();
    Track(ack, message) {
        this.pending.set(ack, message);
    }
    Confirm(ack) {
        const maybe_ack = this.pending.get(ack);
        if (!maybe_ack)
            return null;
        this.pending.delete(ack);
        return maybe_ack;
    }
    Has(ack) {
        return this.pending.has(ack);
    }
}
