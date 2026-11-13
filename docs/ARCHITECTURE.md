# Architecture

| Part | Role |
| --- | --- |
| React and TypeScript | Shared responsive interface and vault workflows |
| Web Worker and libsodium | Password-based key derivation with Argon2id, record encryption, and streaming attachment encryption |
| Tauri and Rust | Desktop packaging and platform integration; Windows uses WebView2 |
| Rust and Axum | Private HTTPS API behind a reverse proxy; session authorization and signed writes |
| SQLite and blob storage | Encrypted revisions and attachment metadata in SQLite; encrypted chunks on disk |

The master password stays on the client. Recovering access on a new device requires the master password and the owner's offline recovery file. Clients encrypt records with XChaCha20-Poly1305 and use authenticated streaming encryption for attachment chunks. Cached edits queue for sync after reconnection, and the client preserves conflicting revisions for review. The server can observe operational metadata such as ciphertext sizes and access times.

The self-hosted API serves one vault owner over private HTTPS. Desktop clients connect to the operator's API URL. A separately hosted browser client uses the exact origin configured by the operator. See the [setup guide](SETUP.md) for deployment, backup and restore.

The web host serves executable client code, so it must be trusted and secured separately from the storage API. A compromised browser, desktop or web host can put an unlocked vault at risk. Keep encrypted backups and recovery material separate. Use synthetic data with the public alpha and verify recovery in a separate installation.
