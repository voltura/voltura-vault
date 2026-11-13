# Set up Voltura Vault 0.1.0-alpha.2

Use synthetic data for this prerelease. Keep the vault API on a private LAN or
an existing VPN such as WireGuard. The operator provides DNS, network access,
and a TLS certificate and key for the API hostname.

Get the desktop package, Docker kit and `SHA256SUMS.txt` from the
[v0.1.0-alpha.2 release](https://github.com/voltura/voltura-vault/releases/tag/v0.1.0-alpha.2).
The Windows installer reached first run in Windows Sandbox. The Ubuntu package
reached first run in a clean Ubuntu 24.04 container. The macOS bundle passed
architecture and signature checks. A scripted client recovered a synthetic note
and attachment in a Docker restore drill. Full pairing, offline reconnect and
restore with the packaged apps, plus interactive macOS testing, remain pending.

## Server

Use a Linux Docker host with Docker Compose, Bash, Python 3, curl and restic.
The Docker kit ZIP includes the server source and builds it locally. Extract it
and work from the extracted directory. Use a separate state directory, TLS
directory and backup destination per vault.

1. Set up DNS so your desktop devices resolve your API hostname to the private
   host interface. Open only the chosen HTTPS port on that private interface.
   Do not forward it from the public internet.
2. Create the state directory owned by UID/GID 10001 with mode 0700. Put
   "fullchain.pem" and "privkey.pem" in the TLS directory. Make that directory
   traversable and both files readable by proxy UID/GID 101 only (or grant an
   equivalent ACL); mount it read-only. If using a private CA, distribute the
   public CA certificate to your devices by a trusted route.
3. Copy "deploy/public/operator.env.example" outside the source tree, set its
   permissions to 0600 and edit it. Use the canonical lower-case API DNS hostname,
   plus a port if other than 443, for "VAULT_API_HOST". Set "VAULT_HTTPS_PORT" to
   that port and "VAULT_BIND_IP" to the private IPv4 address. Configure the
   absolute state and TLS directory paths. The included example binds loopback.
4. Run the following as the operator with access to Docker and the state
   directory. Use a unique "COMPOSE_PROJECT_NAME" for each server on a host.

```sh
bash deploy/public/vaultctl /path/to/operator.env init
bash deploy/public/vaultctl /path/to/operator.env up
bash deploy/public/vaultctl /path/to/operator.env health
```

For private TLS, pass the CA file as the last argument to "health". The API
runs as a non-root user on a Docker network without a published port. The proxy
is the only published service.

Open "data/setup-token" in the private state directory locally. Do not paste it
into terminal commands, logs or chat. It is valid for 15 minutes and can only
be used once. If it expires before setup finishes, run:

```sh
bash deploy/public/vaultctl /path/to/operator.env renew-setup
```

The code is replaced in the same file. After successful setup, remove the old
code file from the operator's state directory.

## Desktop

| Package | Installation |
| --- | --- |
| Windows x64 | Run the NSIS installer. The public alpha has its own product name and application identifier. It is unsigned and may trigger SmartScreen. If WebView2 is missing, the installer needs internet access to download it. |
| Ubuntu 24.04 amd64 | Install the .deb with "sudo apt install ./NAME.deb". |
| Apple Silicon Mac | Extract the ZIP with Archive Utility and move the app into Applications. It is ad hoc signed and unnotarized; macOS may block first launch. |

Verify the published SHA-256 checksums and GitHub attestations. The attestation
uses the build tag, which points to the same commit as the release tag. Replace
`PACKAGE` with the name of the downloaded file.

```sh
sha256sum -c SHA256SUMS.txt
gh attestation verify ./PACKAGE --repo voltura/voltura-vault --source-ref refs/tags/v0.1.0-alpha.2-rc.3 --signer-workflow voltura/voltura-vault/.github/workflows/public-prerelease.yml
```

1. Open **Connect to Vault** and enter the root HTTPS URL. If the issuer is
   unknown, explicitly select the public CA certificate in PEM or DER format.
   Verify it with your operator. Never select a TLS private key. An imported CA
   applies only to that pairing. Hostname, chain and validity checks remain active.
2. For a new vault, enter the setup code and choose a master password. Save the
   generated recovery file offline, then select it to confirm. Run the unlock
   time measurement when prompted. On another device, enter the same URL and
   use the existing master password and recovery file.
3. After the first unlock, Windows users can optionally enable Windows Hello.
   Use the master password for sync. Try a synthetic note and attachment, sync
   them on a second profile, then try offline unlock and reconnect.

The alpha supports one paired server per desktop installation profile. Before
changing servers, save the open edit, sync, and choose **Check before changing
servers** in Settings. Pair the other server in a fresh OS account or VM. The
existing encrypted cache stays in its original profile, including any unsynced
changes. Do not manually delete its application data.

## Back up and restore

Mount a dedicated external disk or NAS on the Docker host. Confirm it is mounted
before a scheduled run. The Vault app does not need its credentials. Use an
existing, separate repository directory on that mount and a password file with
mode 0600 or 0400 outside Vault state and the repository. Keep an offline copy
of the repository password apart from the vault recovery file.

```sh
restic --repo /mnt/vault-backup/repo --password-file /path/to/password-file init
bash deploy/public/vaultctl /path/to/operator.env backup /mnt/vault-backup/repo /path/to/password-file
restic --repo /mnt/vault-backup/repo --password-file /path/to/password-file snapshots
bash deploy/public/vaultctl /path/to/operator.env restore /mnt/vault-backup/repo /path/to/password-file FULL_SNAPSHOT_ID /srv/vault-restore
```

Backups pause the API while copying SQLite (including a WAL if present) and
encrypted attachment chunks into restic, and restart a previously running API
on success or failure. Schedule the backup command on the Docker host via a
systemd timer or cron. Schedule regular "restic check" runs and retain enough
history to recover a known good copy. Keep a separate offline copy.

Restore verifies restic's files, checks SQLite integrity and foreign keys,
checks published chunk paths and lengths, clears sessions and changes the sync
generation. Before using a restored server, check the selected snapshot and
the expected key epoch with an independent recovery record. Run the restored
server under a separate Compose project, state root and HTTPS endpoint. From a
clean desktop profile, recover using the original recovery file and password,
then check the expected note and compare the downloaded attachment bytes. Do
this drill with a disposable vault before relying on backups.

## Optional browser client

Serve the browser app on a separate trusted HTTPS origin. Set that origin in
"VAULT_BROWSER_ORIGIN" on the API server and in the build environment as
"VOLTURA_WEB_ORIGIN". Set "VOLTURA_WEB_API_ORIGIN" in the build environment to
the API's HTTPS origin. These are origins without a trailing slash. Build with
"npm ci" and "npm run build", and allow only the exact API origin in the
hosted site's "connect-src" policy. The browser uses system certificate
trust and bearer sessions. Control who can change the hosted client: it can
read plaintext on an unlocked device.

## Try the vault with synthetic data

- Edit an item offline, reconnect and sync. If two devices edit the same item,
  review the conflicting revisions before choosing which changes to keep.
- Attach a file up to 100 MB. Try downloading it on demand, keeping it offline
  and deleting it with confirmation. Earlier backups can still contain the file.
- In **Settings → Import from Bitwarden**, preview a personal plaintext or
  password-protected JSON export. The preview reports duplicates and changed
  items. Changed records are skipped for manual review. Transfer attachment
  files separately. The importer refuses exports with organization ownership
  or items that require password re-prompt.

## Build from source

Use the pinned Rust toolchain, Node.js 26.13.0 and the
[Tauri system prerequisites](https://v2.tauri.app/start/prerequisites/).
For a local browser preview, run "npm ci", "npm run check", "npm test" and
"npm run dev". For the desktop build run:

```sh
npm ci
npm run desktop:build -- --config src-tauri/tauri.public.conf.json --bundles nsis -- --locked
```

Use "deb" on Ubuntu 24.04 or "app" on Apple Silicon. The build contains no
operator certificate or server address. See the
[release workflow](../.github/workflows/public-prerelease.yml) for packaging.
