# Build and set up Voltura Vault

## Local preview

Install Node.js 24+ and npm. Run:

```sh
npm ci
npm run check
npm test
npm run dev
```

Open the local URL printed by Vite. The local preview is for sample data. It does not connect to a deployed server.

## Self-hosting

This source release is for operators comfortable setting up private HTTPS, DNS, a reverse proxy and backup storage.

1. Choose distinct client and API hostnames. The source uses `vault-ui.test` and `vault-api.test`. Replace those placeholders consistently in the browser client, Rust API allowlist, and any Tauri profiles you build. Use `git grep -n -e vault-api.test -e vault-ui.test` to find the configuration and matching tests.
2. Build the API with `cargo build --locked --release -p voltura-vault-server`. A Dockerfile is also provided. Give the service a dedicated account and a private persistent data directory.
3. Initialize a new directory with `voltura-vault-server init /path/to/data` and start it with `voltura-vault-server run /path/to/data`. Keep the generated setup token private. It expires 15 minutes after initialization.
4. Keep the API on a private network or VPN. Use a trusted TLS certificate at the reverse proxy, preserve the API hostname, and restrict browser requests to the configured client origin. Keep administrative access separate from vault access.
5. Run `npm run build` and host the static `dist/` files over HTTPS separately from the storage API. For a deployment build, set `VOLTURA_PRODUCTION_RELEASE=1` in the build environment. Control who can change the hosted client: it runs on the device that handles plaintext.
6. Use the setup code in the client, save the recovery file offline, and test unlock, sync and recovery with sample data. Back up the database and encrypted attachment store together; verify a restore in an isolated environment before importing real credentials.

## Desktop builds

Install the Rust toolchain pinned in `rust-toolchain.toml` and the [Tauri system prerequisites](https://v2.tauri.app/start/prerequisites/). After `npm ci`, build on Windows with `npm run desktop:build -- --config src-tauri/tauri.vpn.conf.json`. Build Linux or macOS previews on the target OS with the `src-tauri/tauri.unix.conf.json` profile. The published source does not include signing keys or trust material for anyone’s installation.
