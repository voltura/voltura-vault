import { expect, it } from 'vitest';
import { calibrate } from '../src/calibration';

it('corrects an overshoot and reports the timing for the selected parameters', () => {
  const result = calibrate(passes => passes === 3 ? 440 : passes === 34 ? 8560 : 5000, new Uint8Array(16), () => {});
  expect(result.samples.map(s => s.passes)).toEqual([3, 34, 20]);
  expect(result.kdf.passes).toBe(20);
  expect(result.measuredMs).toBe(5000);
  expect(result.targetReached).toBe(true);
  expect(result.kdf.memory).toBe(128 * 1024 ** 2);
});

it('never calls a timing outside the target a passed calibration', () => {
  const result = calibrate(() => 12_000, new Uint8Array(16), () => {});
  expect(result.kdf.passes).toBe(3);
  expect(result.targetReached).toBe(false);
  expect(() => calibrate(() => NaN, new Uint8Array(16), () => {})).toThrow();
});

it('stops at the parameter ceiling without pretending the target was reached', () => {
  const result = calibrate(() => 5, new Uint8Array(16), () => {});
  expect(result.samples.map(s => s.passes)).toEqual([3, 64]);
  expect(result.targetReached).toBe(false);
});
