import { webcrypto } from 'node:crypto';
import { afterEach, expect, it, vi } from 'vitest';
import { enrollHello, evaluateHello } from '../src/hello';

afterEach(() => vi.unstubAllGlobals());

it('uses a creation PRF result only after verifying a local Windows Hello credential', async () => {
  const origin = 'https://vault-ui.test';
  const authenticatorData = new Uint8Array(55);
  authenticatorData.set(new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(new URL(origin).hostname))));
  authenticatorData[32] = 0x45;
  authenticatorData.set(Uint8Array.from(Buffer.from('6028b017b1d44c02b4b3afcdafc96bb2', 'hex')), 37);
  const first = new Uint8Array(32).fill(7);
  const create = vi.fn().mockResolvedValue({
    id: 'AQID',
    authenticatorAttachment: 'platform',
    response: { getAuthenticatorData: () => authenticatorData },
    getClientExtensionResults: () => ({ prf: { results: { first } } }),
  });
  vi.stubGlobal('window', {});
  vi.stubGlobal('location', { origin });
  vi.stubGlobal('navigator', { platform: 'Win32', credentials: { create } });
  vi.stubGlobal('PublicKeyCredential', class {});

  const enrollment = await enrollHello();
  expect(enrollment.secret).toEqual(first);
  expect(create.mock.calls[0][0].publicKey.extensions.prf.eval.first).toEqual(enrollment.credential.input);
  authenticatorData[32] |= 8;
  await expect(enrollHello()).rejects.toThrow('Choose Windows Hello on this PC');
});

it('requests the enrolled credential only and rejects backed-up or different credentials', async () => {
  const origin = 'https://vault-ui.test';
  const id = '-_8';
  const input = new Uint8Array(32).fill(7);
  const authenticatorData = new Uint8Array(37);
  authenticatorData.set(new Uint8Array(await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(new URL(origin).hostname))));
  authenticatorData[32] = 5;
  const assertion = {
    id,
    response: { authenticatorData },
    getClientExtensionResults: () => ({ prf: { results: { first: new Uint8Array(32).fill(3) } } }),
  };
  const get = vi.fn().mockResolvedValue(assertion);
  vi.stubGlobal('window', {});
  vi.stubGlobal('location', { origin });
  vi.stubGlobal('navigator', { platform: 'Win32', credentials: { get } });
  vi.stubGlobal('PublicKeyCredential', class {});

  await expect(evaluateHello({ id, input })).resolves.toEqual(new Uint8Array(32).fill(3));
  expect(get.mock.calls[0][0].publicKey).toMatchObject({ rpId: new URL(origin).hostname, hints: ['client-device'], userVerification: 'required' });
  expect(get.mock.calls[0][0].publicKey.allowCredentials).toEqual([{ type: 'public-key', id: new Uint8Array([251, 255]) }]);
  authenticatorData[32] = 5 | 8;
  await expect(evaluateHello({ id, input })).rejects.toThrow('Choose Windows Hello on this PC');
  authenticatorData[32] = 5;
  assertion.id = 'other';
  await expect(evaluateHello({ id, input })).rejects.toThrow('Windows Hello did not return the passkey registered for this vault.');
});
