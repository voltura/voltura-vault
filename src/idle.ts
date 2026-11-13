export class IdleClock {
  private lastInteraction: number;
  private lastObserved: number;
  constructor(private timeoutMs: number, now = Date.now()) { this.lastInteraction = now; this.lastObserved = now; }
  expired(now = Date.now()): boolean {
    const expired = now < this.lastObserved || now - this.lastInteraction >= this.timeoutMs;
    this.lastObserved = now;
    return expired;
  }
  interact(now = Date.now()): boolean {
    if (this.expired(now)) return false;
    this.lastInteraction = now; return true;
  }
}
