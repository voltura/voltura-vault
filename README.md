# Voltura Vault

<img src="assets/vault-safe.png" width="96" height="96" alt="Voltura Vault safe">

A self-hosted password manager for logins, secure notes, SSH keys and files. The app encrypts items and attachments on your device before syncing them to a server you operate.

[Download v0.1.1](https://github.com/voltura/voltura-vault/releases/tag/v0.1.1) · [Product website](https://voltura-vault.voltura.se/) · [Setup and builds](docs/SETUP.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md)

## What it does

- Organize logins, cards, identities, notes and SSH keys with folders, search and custom fields.
- Generate passwords, passphrases and usernames. Preview personal Bitwarden JSON imports, including password-protected exports, and see duplicate or changed items before importing.
- Download encrypted attachments up to 100 MB on demand, keep selected files offline, or delete them with confirmation.
- Edit cached items offline and sync when you reconnect. Review conflicting edits when two devices change the same item.
- Recover access on a new device with your master password and offline recovery file. The Docker kit includes encrypted backup and restore with restic.

## Start here

The public prerelease provides desktop packages for Windows x64, Ubuntu 24.04 amd64 and Apple Silicon macOS, plus a Docker kit for the private HTTPS API. You can also build and host the browser app separately. Use synthetic data while evaluating the alpha and practice restoring a backup. See the [setup guide](docs/SETUP.md) for platform checks and pairing instructions.

## Support development

Voltura Vault is built by [Voltura AB](https://voltura.se/). Support development through [Ko-fi](https://ko-fi.com/G2G74W5F8) or [PayPal](https://www.paypal.com/donate?hosted_button_id=7PN65YXN64DBG).

## License

Voltura Vault source code is [MIT licensed](LICENSE), © 2026 Voltura AB. Dependencies and wordlists retain their own licenses; see the [wordlist sources and attribution](src/dictionaries/SOURCES.md).
