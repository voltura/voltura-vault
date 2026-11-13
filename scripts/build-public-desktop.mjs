import { spawnSync } from 'node:child_process';
const result = spawnSync('npm run build', { shell: true, stdio: 'inherit',
  env: { ...process.env, VOLTURA_PUBLIC_DESKTOP: '1', VOLTURA_PRODUCTION_RELEASE: '0' } });
process.exit(result.status ?? 1);
