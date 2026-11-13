import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { expect, it, vi } from 'vitest';

it('uses the precached shell when navigation fails and preserves a successful network response', async () => {
  const work = await mkdtemp(join(tmpdir(), 'voltura-offline-shell-'));
  try {
    await mkdir(join(work, 'dist'));
    await writeFile(join(work, 'dist', 'index.html'), '<p>Synthetic offline shell</p>');
    const builder = fileURLToPath(new URL('../scripts/build-sw.mjs', import.meta.url));
    execFileSync(process.execPath, [builder], { cwd: work });

    const listeners = new Map<string, (event: unknown) => void>();
    const fetch = vi.fn<() => Promise<Response>>();
    const cached = new Response('Synthetic offline shell');
    const match = vi.fn<() => Promise<Response | undefined>>().mockResolvedValue(cached);
    const origin = 'https://vault-ui.test';
    runInNewContext(await readFile(join(work, 'dist', 'sw.js'), 'utf8'), {
      self: { addEventListener: listeners.set.bind(listeners), location: { origin } },
      caches: { open: async () => ({ match }) },
      fetch, URL, Response,
    });

    const navigate = (path: string) => new Promise<Response>(resolve => {
      listeners.get('fetch')!({ request: { url: origin + path, method: 'GET', mode: 'navigate' }, respondWith: resolve });
    });

    const online = new Response('Synthetic online shell');
    fetch.mockResolvedValueOnce(online);
    await expect(navigate('/')).resolves.toBe(online);
    expect(match).not.toHaveBeenCalled();

    for (const status of [404, 503]) {
      fetch.mockResolvedValueOnce(new Response(null, { status }));
      await expect(navigate('/index.html')).resolves.toBe(cached);
    }
    fetch.mockRejectedValueOnce(new TypeError('Network unavailable'));
    await expect(navigate('/')).resolves.toBe(cached);
    expect(match).toHaveBeenCalledWith('/index.html');

    match.mockResolvedValue(undefined);
    const unavailable = new Response(null, { status: 503 });
    fetch.mockResolvedValueOnce(unavailable);
    await expect(navigate('/')).resolves.toBe(unavailable);
    fetch.mockRejectedValueOnce(new TypeError('Network unavailable'));
    await expect(navigate('/')).resolves.toMatchObject({ type: 'error' });
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});
