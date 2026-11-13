import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import packageInfo from './package.json' with { type: 'json' };

const buildVersion = `${packageInfo.version}+${Date.now().toString(36)}`;

export default defineConfig({
  define: {
    'import.meta.env.VITE_VAULT_BUILD_VERSION': JSON.stringify(buildVersion),
    'import.meta.env.VITE_VAULT_PRODUCTION_RELEASE': JSON.stringify(process.env.VOLTURA_PRODUCTION_RELEASE === '1'),
  },
  plugins: [react(), {
    name: 'vault-version',
    apply: 'build',
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'version.json', source: JSON.stringify({ version: buildVersion }) });
    },
  }],
  server: { port: 1420, strictPort: true },
  test: { include: ['tests/**/*.test.ts'] },
  preview: { port: 1421, strictPort: true },
  worker: { format: 'es' },
  build: { target: 'es2022', sourcemap: false },
});
