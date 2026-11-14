#!/usr/bin/python3 -I
"""Stream a consistent ciphertext snapshot under the isolated backup account."""

import base64
import hashlib
import fcntl
import json
import os
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
from contextlib import closing, contextmanager
from pathlib import Path

DATA = Path("/var/lib/voltura-vault")
PUBLISHED = Path("/var/lib/voltura-vault-published")
CHUNK_BYTES = 1_048_576
MAX_FILE_BYTES = 100_000_000


class SealedSnapshot:
    def __init__(self, archive, recipient, cache, age):
        self.archive = archive
        self.recipient = recipient
        self.cache = cache
        self.age = age
        self.used = set()

    def addfile(self, entry, source, digest):
        cache_id = hashlib.sha256(f"{self.recipient}:{digest}".encode("ascii")).hexdigest()
        encrypted = self.cache / cache_id
        if not encrypted.is_file():
            with tempfile.NamedTemporaryFile(dir=self.cache, delete=False) as pending:
                temporary = Path(pending.name)
                try:
                    subprocess.run([self.age, "-r", self.recipient], stdin=source,
                                   stdout=pending, check=True, timeout=600)
                    temporary.replace(encrypted)
                finally:
                    temporary.unlink(missing_ok=True)
        self.used.add(cache_id)
        with encrypted.open("rb") as contents:
            sealed_entry = tarfile.TarInfo(entry.name + ".age")
            sealed_entry.mode = 0o600
            sealed_entry.size = os.fstat(contents.fileno()).st_size
            self.archive.addfile(sealed_entry, contents)

    def prune(self):
        for file in self.cache.iterdir():
            if file.name not in self.used and file.name != ".lock":
                file.unlink()


def write_entry(archive, entry, source, digest):
    if isinstance(archive, SealedSnapshot):
        archive.addfile(entry, source, digest)
    else:
        archive.addfile(entry, source)


@contextmanager
def directory(parent, name):
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def add_file(archive, manifest, parent, name, member, minimum, maximum):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
    )
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not minimum <= metadata.st_size <= maximum:
            raise ValueError("Snapshot contains a missing or invalid file")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        source.seek(0)
        entry = tarfile.TarInfo(member)
        entry.size = metadata.st_size
        entry.mode = 0o600
        write_entry(archive, entry, source, digest)
        manifest[member] = {"size": entry.size, "sha256": digest}


def capture_database(source_path, snapshot):
    deadline = time.monotonic() + 60

    def check_deadline(*_):
        if time.monotonic() > deadline:
            raise TimeoutError("SQLite snapshot timed out")

    with closing(sqlite3.connect(source_path.as_uri() + "?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination, pages=64, progress=check_deadline)
            destination.execute("PRAGMA foreign_keys=ON")
            destination.execute("PRAGMA secure_delete=ON")
            destination.execute("DELETE FROM sessions")
            schema = destination.execute("PRAGMA user_version").fetchone()[0]
            if schema >= 8:
                destination.execute("DELETE FROM used_sync_refreshes")
                destination.execute("DELETE FROM sync_devices")
            destination.execute("DELETE FROM files WHERE published IS NULL")
            destination.commit()
            if destination.execute("PRAGMA journal_mode=DELETE").fetchone() != ("delete",):
                raise ValueError("Could not consolidate the SQLite snapshot")
            if schema >= 8:
                destination.execute("VACUUM")
            if destination.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                raise ValueError("SQLite snapshot failed its integrity check")
            if destination.execute("PRAGMA foreign_key_check").fetchone():
                raise ValueError("SQLite snapshot failed its foreign key check")
            epoch = (destination.execute("SELECT key_epoch FROM owner WHERE singleton=1").fetchone() or (1,))[0] if schema >= 4 else 1
            return epoch, destination.execute(
                "SELECT object, size FROM files WHERE published IS NOT NULL ORDER BY object"
            ).fetchall()


def export(data, published, output, recipient=None, cache=None, age="/usr/bin/age", signing_key=None):
    captured_at = int(time.time())
    with tempfile.TemporaryDirectory(prefix="voltura-backup-") as staging:
        epoch, files = capture_database(data / "vault.sqlite3", Path(staging) / "vault.sqlite3")
        with tarfile.open(fileobj=output, mode="w|", format=tarfile.USTAR_FORMAT) as tar:
            archive = SealedSnapshot(tar, recipient, cache, age) if recipient else tar
            manifest = {}
            with directory(None, staging) as db_dir:
                add_file(archive, manifest, db_dir, "vault.sqlite3", "vault.sqlite3", 1, 1024**3)
            if files:
                blob_path = Path("vault.blobs") if epoch == 1 else Path("vault.blobs") / f"epoch-{epoch}"
                with directory(None, data / blob_path) as blobs:
                    for object_id, size in files:
                        if str(uuid.UUID(object_id)) != object_id or not 0 <= size <= MAX_FILE_BYTES:
                            raise ValueError("Invalid published attachment metadata")
                        with directory(blobs, object_id) as attachment:
                            for index in range(max(1, (size + CHUNK_BYTES - 1) // CHUNK_BYTES)):
                                expected = min(size - index * CHUNK_BYTES, CHUNK_BYTES) + 17
                                chunk = str(index)
                                add_file(archive, manifest, attachment, chunk,
                                         f"{blob_path.as_posix()}/{object_id}/{chunk}", expected, expected)
            for kind, suffix, maximum in (
                ("source-archives", ".vvsa", 65 * CHUNK_BYTES),
                ("recovery-kits", ".vvkr", CHUNK_BYTES + 53),
            ):
                for base in (published, data):
                    try:
                        archives = os.open(base / kind, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    except FileNotFoundError:
                        continue
                    try:
                        for name in sorted(os.listdir(archives)):
                            if not name.endswith(suffix):
                                continue
                            stem = name.removesuffix(suffix)
                            if str(uuid.UUID(stem)) != stem:
                                raise ValueError("Invalid source or recovery archive identifier")
                            member = f"{kind}/{name}"
                            if member not in manifest:
                                add_file(archive, manifest, archives, name, member, 1, maximum)
                    finally:
                        os.close(archives)
            if signing_key is None:
                serialized = json.dumps({"version": 1, "files": manifest}, sort_keys=True).encode()
            else:
                payload = json.dumps({"version": 2, "capturedAt": captured_at, "files": manifest},
                                     sort_keys=True).encode()
                signature = subprocess.run(
                    ["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(signing_key),
                     "-n", "voltura-backup", "-"], input=payload, stdout=subprocess.PIPE,
                    check=True, timeout=30,
                ).stdout
                serialized = json.dumps({"payload": base64.b64encode(payload).decode("ascii"),
                                         "signature": signature.decode("ascii")}).encode()
            entry = tarfile.TarInfo("snapshot-manifest.json")
            entry.size = len(serialized)
            entry.mode = 0o600
            with tempfile.TemporaryFile() as contents:
                contents.write(serialized)
                contents.seek(0)
                write_entry(archive, entry, contents, hashlib.sha256(serialized).hexdigest())
        if isinstance(archive, SealedSnapshot):
            output.flush()
            archive.prune()


if __name__ == "__main__":
    if sys.argv[1:] != ["--seal"]:
        sys.exit("The Vault backup exporter requires --seal.")
    os.umask(0o077)
    try:
        recipient = Path("/etc/voltura-backup-recipient").read_text(encoding="ascii").strip()
        if not recipient.startswith("age1") or len(recipient) != 62 or not recipient.isalnum():
            raise ValueError("Expected an age X25519 public recipient")
        cache = Path("/var/cache/voltura-vault-backup-export")
        with (cache / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            export(DATA, PUBLISHED, sys.stdout.buffer, recipient, cache,
                   signing_key=Path("/etc/voltura-backup-signing-v2/id_ed25519"))
    except (OSError, sqlite3.Error, ValueError, tarfile.TarError, subprocess.SubprocessError):
        sys.exit("Vault backup export failed. Discard the partial snapshot.")
