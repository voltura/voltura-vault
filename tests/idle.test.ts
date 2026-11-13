import { describe, expect, it } from 'vitest';
import { IdleClock } from '../src/idle';
describe('idle clock', () => {
  it('counts time in the background and cannot be revived by a late interaction', () => {
    const clock = new IdleClock(300_000, 1000);
    expect(clock.expired(300_999)).toBe(false);
    expect(clock.interact(301_000)).toBe(false);
  });
  it('resets only after a deliberate timely interaction', () => {
    const clock = new IdleClock(300_000, 1000);
    expect(clock.interact(200_000)).toBe(true);
    expect(clock.expired(400_000)).toBe(false);
    expect(clock.expired(500_000)).toBe(true);
  });
  it('forces lock on backward wall-clock movement', () => {
    const clock = new IdleClock(300_000, 1000);
    expect(clock.expired(2000)).toBe(false); expect(clock.expired(1999)).toBe(true);
  });
});
