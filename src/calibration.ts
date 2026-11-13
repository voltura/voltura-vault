import type { Kdf } from './format';

export type Calibration = { kdf: Kdf; measuredMs: number; samples: { passes: number; ms: number }[]; targetReached: boolean };
// Calibration is performed before an envelope exists. It never changes an enrolled envelope.
export function calibrate(measure: (passes: number) => number, salt: Uint8Array, progress: (passes: number, ms: number) => void): Calibration {
  const samples: Calibration['samples'] = [];
  let passes = 3;
  let best: { passes: number; ms: number } | undefined;
  for (let attempt = 0; attempt < 6; attempt++) {
    const ms = measure(passes);
    if (!Number.isFinite(ms) || ms <= 0) throw Error('Calibration did not produce a valid timing. Run it again.');
    const sample = { passes, ms: Math.round(ms) }; samples.push(sample); progress(passes, sample.ms);
    if (!best || Math.abs(ms - 5000) < Math.abs(best.ms - 5000)) best = sample;
    if (ms >= 4500 && ms <= 6500) break;
    const next = Math.min(64, Math.max(3, Math.round(passes * 5000 / ms)));
    if (next === passes) break;
    passes = next;
  }
  return { kdf: { algorithm: 'argon2id13', memory: 128 * 1024 ** 2, salt, passes: best!.passes }, measuredMs: best!.ms, samples, targetReached: best!.ms >= 4500 && best!.ms <= 6500 };
}
