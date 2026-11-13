import sharp from 'sharp';
import { mkdir, writeFile } from 'node:fs/promises';

const safe = 'assets/vault-safe.png';
const installerArt = 'assets/installer-safe.jpg';
const navy = '#071525';

for (const [name, size] of [['icon-192', 192], ['icon-512', 512]]) {
  const inset = Math.round(size * 0.04);
  await sharp(safe).resize(size - 2 * inset, size - 2 * inset)
    .extend({ top: inset, bottom: inset, left: inset, right: inset, background: '#00000000' })
    .png().toFile(`public/${name}.png`);
}
for (const [name, size, inset] of [['apple-touch-icon', 180, 16], ['icon-maskable-512', 512, 112]]) {
  await sharp(safe).resize(size - 2 * inset, size - 2 * inset).flatten({ background: navy })
    .extend({ top: inset, bottom: inset, left: inset, right: inset, background: navy })
    .png().toFile(`public/${name}.png`);
}

const icoSizes = [16, 24, 32, 48, 64, 128, 256];
const frames = await Promise.all(icoSizes.map(size => sharp(safe).resize(size, size).png().toBuffer()));
const directory = Buffer.alloc(6 + frames.length * 16);
directory.writeUInt16LE(1, 2);
directory.writeUInt16LE(frames.length, 4);
let imageOffset = directory.length;
for (const [index, frame] of frames.entries()) {
  const entry = 6 + index * 16;
  directory[entry] = directory[entry + 1] = icoSizes[index] % 256;
  directory.writeUInt16LE(1, entry + 4);
  directory.writeUInt16LE(32, entry + 6);
  directory.writeUInt32LE(frame.length, entry + 8);
  directory.writeUInt32LE(imageOffset, entry + 12);
  imageOffset += frame.length;
}
const ico = Buffer.concat([directory, ...frames]);
await mkdir('src-tauri/icons', { recursive: true });
await writeFile('public/favicon.ico', ico);
await writeFile('src-tauri/icons/icon.ico', ico);
await sharp(safe).resize(128, 128).png().toFile('src-tauri/icons/icon.png');

async function writeInstallerBitmap(name, width, height, artwork, background) {
  const rgb = await sharp({ create: { width, height, channels: 3, background } })
    .composite([artwork]).removeAlpha().raw().toBuffer();
  const stride = Math.ceil(width * 3 / 4) * 4;
  const bitmap = Buffer.alloc(54 + stride * height);
  bitmap.write('BM', 0);
  bitmap.writeUInt32LE(bitmap.length, 2);
  bitmap.writeUInt32LE(54, 10);
  bitmap.writeUInt32LE(40, 14);
  bitmap.writeInt32LE(width, 18);
  bitmap.writeInt32LE(height, 22);
  bitmap.writeUInt16LE(1, 26);
  bitmap.writeUInt16LE(24, 28);
  bitmap.writeUInt32LE(stride * height, 34);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const source = (y * width + x) * 3;
      const target = 54 + (height - 1 - y) * stride + x * 3;
      bitmap[target] = rgb[source + 2];
      bitmap[target + 1] = rgb[source + 1];
      bitmap[target + 2] = rgb[source];
    }
  }
  await writeFile(`src-tauri/icons/installer-${name}.bmp`, bitmap);
}

await writeInstallerBitmap('sidebar', 164, 314, {
  input: await sharp(installerArt).resize(164, 164).png().toBuffer(), left: 0, top: 73,
}, navy);
await writeInstallerBitmap('header', 150, 57, {
  input: await sharp(safe).resize(44, 44).png().toBuffer(), left: 94, top: 6,
}, '#ffffff');
