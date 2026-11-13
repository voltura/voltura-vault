import { readdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
async function walk(dir) {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const path = `${dir}/${e.name}`;
    if (e.isDirectory()) out.push(...await walk(path));
    else if (e.name !== 'sw.js' && path !== 'dist/version.json') out.push(path);
  }
  return out.sort();
}
const files = await walk('dist'), hash = createHash('sha256');
for (const f of files) hash.update(await readFile(f));
const name = `voltura-vault-${hash.digest('hex').slice(0, 16)}`;
// Activate the new cache without reloading any open page. Keep previous hashed assets
// so an older page can still start its worker or load a lazy chunk after activation.
await writeFile('dist/sw.js', `const CACHE=${JSON.stringify(name)};
const ASSETS=${JSON.stringify(files.map(f => f.slice(4)))};
self.addEventListener('install', e => e.waitUntil((async () => {
  const cache = await caches.open(CACHE);
  await cache.addAll(ASSETS.map(path => new Request(path, { cache: 'reload' })));
  await self.skipWaiting();
})()));
self.addEventListener('activate', e => e.waitUntil((async () => {
  const previous = (await caches.keys()).filter(key => key.startsWith('voltura-vault-') && key !== CACHE);
  await Promise.all(previous.slice(0, -2).map(key => caches.delete(key)));
})()));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (e.request.mode === 'navigate' && (url.pathname === '/' || url.pathname === '/index.html')) {
    e.respondWith((async () => {
      const response = await fetch(e.request, { cache: 'no-cache' }).catch(() => undefined);
      if (response?.ok) return response;
      const shell = await (await caches.open(CACHE)).match('/index.html');
      return shell ?? response ?? Response.error();
    })());
    return;
  }
  if (ASSETS.includes(url.pathname)) {
    e.respondWith((async () => (await (await caches.open(CACHE)).match(url.pathname)) || fetch(e.request))());
  } else if (url.pathname.startsWith('/assets/')) {
    e.respondWith((async () => {
      const previous = (await caches.keys()).filter(key => key.startsWith('voltura-vault-') && key !== CACHE).reverse();
      for (const key of previous) {
        const asset = await (await caches.open(key)).match(url.pathname);
        if (asset) return asset;
      }
      return fetch(e.request);
    })());
  }
});
`);
console.log(`Offline shell: ${files.length} assets, ${name}`);
