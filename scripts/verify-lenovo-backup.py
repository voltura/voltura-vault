"""Validate a pulled Vault snapshot and publish it to a new local directory."""

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
MANIFEST = "snapshot-manifest.json"
CHUNK_BYTES = 1_048_576
MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_MEMBERS = 120_000
LIMITS = (
    (re.compile(r"vault\.sqlite3"), 1024**3),
    (re.compile(rf"vault\.blobs/(?:epoch-[1-9][0-9]{{0,9}}/)?{UUID}/(?:0|[1-9][0-9]?)"), CHUNK_BYTES + 17),
    (re.compile(rf"source-archives/{UUID}\.vvsa"), 65 * CHUNK_BYTES),
    (re.compile(rf"recovery-kits/{UUID}\.vvkr"), CHUNK_BYTES + 53),
)


class SnapshotEntry(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        entry = super().frombuf(buffer, encoding, errors)
        if entry.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            raise ValueError("Only regular USTAR snapshot entries are allowed")
        return entry


def verify_and_extract(source, destination, sealed=False):
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Snapshot destination already exists")
    if source.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Snapshot exceeds the backup size limit")
    with tempfile.TemporaryDirectory(prefix=".voltura-stage-", dir=destination.parent) as temp:
        stage = Path(temp) / "snapshot"
        stage.mkdir(mode=0o700)
        files = {}
        manifest = None
        names = set()
        total = 0
        with tarfile.open(source, mode="r:", tarinfo=SnapshotEntry) as archive:
            for member in archive:
                total += member.size
                if len(names) >= MAX_MEMBERS or total > MAX_ARCHIVE_BYTES:
                    raise ValueError("Snapshot exceeds the backup inventory limit")
                if not member.isfile() or not member.size > 0 or MANIFEST in names:
                    raise ValueError("Unexpected snapshot entry")
                name = member.name
                if sealed:
                    if not name.endswith(".age"):
                        raise ValueError("Expected an encrypted snapshot entry")
                    name = name.removesuffix(".age")
                limit = (32 * CHUNK_BYTES if name == MANIFEST else
                         next((limit for pattern, limit in LIMITS if pattern.fullmatch(name)), 0))
                if not limit or member.size > limit + (limit // 4096 + 4096 if sealed else 0) or name in names:
                    raise ValueError("Unexpected snapshot path or size")
                names.add(name)
                if name == MANIFEST and not sealed:
                    with archive.extractfile(member) as contents:
                        manifest = json.load(contents)
                    continue
                target = stage / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                digest = hashlib.sha256()
                with archive.extractfile(member) as contents, target.open("xb") as output:
                    if sealed:
                        header = b"age-encryption.org/v1\n-> X25519 "
                        if contents.read(len(header)) != header:
                            raise ValueError("Invalid age snapshot header")
                        output.write(header)
                        shutil.copyfileobj(contents, output, CHUNK_BYTES)
                        continue
                    while block := contents.read(CHUNK_BYTES):
                        digest.update(block)
                        output.write(block)
                files[member.name] = {"size": target.stat().st_size, "sha256": digest.hexdigest()}
        if "vault.sqlite3" not in names or MANIFEST not in names:
            raise ValueError("Snapshot is incomplete")
        if not sealed and manifest != {"version": 1, "files": files}:
            raise ValueError("Snapshot did not match its manifest")
        stage.rename(destination)
        return len(names) - 1


class RestoreMember(tarfile.TarInfo):
    @classmethod
    def frombuf(cls, buffer, encoding, errors):
        member = super().frombuf(buffer, encoding, errors)
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE):
            raise ValueError('Unexpected NAS restore archive member type')
        return member


def extract_snapshot(source, stage):
    if source.seek(0, 2) > MAX_ARCHIVE_BYTES:
        raise ValueError('NAS restore archive exceeds the recovery limit')
    source.seek(0)
    seen = set()
    total = 0
    with tarfile.open(fileobj=source, mode='r:', tarinfo=RestoreMember) as tar:
        for member in tar:
            if len(seen) >= MAX_MEMBERS or member.name in seen:
                raise ValueError('Unexpected NAS restore archive inventory')
            seen.add(member.name)
            total += member.size
            if total > MAX_ARCHIVE_BYTES:
                raise ValueError('NAS restore archive exceeds the recovery limit')
            if member.isdir():
                if member.size != 0:
                    raise ValueError('Unexpected NAS restore directory size')
                continue
            if not member.name.startswith('snapshot/') or not member.name.endswith('.age'):
                raise ValueError('Unexpected NAS restore archive path')
            name = member.name[len('snapshot/'):-len('.age')]
            limit = (32 * CHUNK_BYTES if name == MANIFEST else
                     next((bound for pattern, bound in LIMITS if pattern.fullmatch(name)), 0))
            if not limit or not 0 < member.size <= limit + limit // 4096 + 4096:
                raise ValueError('Unexpected NAS restore archive entry size or path')
            target = stage / 'snapshot' / (name + '.age')
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as contents, target.open('xb') as output:
                shutil.copyfileobj(contents, output, CHUNK_BYTES)


def verify_manifest(path, signers, not_before, allow_legacy, not_after=None):
    manifest = json.loads(path.read_bytes())
    if not isinstance(manifest, dict):
        raise ValueError("Invalid backup manifest")
    if manifest.keys() == {"version", "files"} and manifest["version"] == 1 and allow_legacy:
        return manifest["files"]
    if manifest.keys() != {"payload", "signature"} or signers is None or not_before is None:
        raise ValueError("Expected a signed manifest, a trusted signer and an independent cutoff")
    if not isinstance(manifest["payload"], str) or not isinstance(manifest["signature"], str) or len(manifest["signature"]) > 4096:
        raise ValueError("Invalid backup signature")
    payload = base64.b64decode(manifest["payload"], validate=True)
    signature = path.with_suffix(".sig")
    signature.write_bytes(manifest["signature"].encode("ascii"))
    subprocess.run(["ssh-keygen", "-Y", "verify", "-f", str(signers), "-I", "voltura-lenovo",
                    "-n", "voltura-backup", "-s", str(signature)],
                   input=payload, stdout=subprocess.DEVNULL, check=True, timeout=30)
    signature.unlink()
    signed = json.loads(payload)
    if not isinstance(signed, dict) or signed.keys() != {"version", "capturedAt", "files"} or signed["version"] != 2:
        raise ValueError("Invalid signed backup metadata")
    timestamp = signed["capturedAt"]
    upper = min(time.time() + 300, not_after) if not_after is not None else time.time() + 300
    if type(timestamp) is not int or not 0 < not_before <= timestamp <= upper:
        raise ValueError("Backup capture time is outside the trusted window")
    return signed["files"]


def restore(source, destination, identity, age="age", *, signers=None, not_before=None, allow_legacy=False, not_after=None):
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("Snapshot destination already exists")
    with tempfile.TemporaryDirectory(prefix=".voltura-restore-", dir=destination.parent) as temp:
        plain = Path(temp) / "snapshot"
        plain.mkdir(mode=0o700)
        files = {}
        manifest = None
        manifest_file = source / (MANIFEST + ".age")
        for encrypted in [manifest_file, *sorted(path for path in source.rglob("*") if path != manifest_file)]:
            if encrypted.is_dir() and not encrypted.is_symlink():
                continue
            path = encrypted.relative_to(source).as_posix()
            name = path.removesuffix(".age")
            limit = (32 * CHUNK_BYTES if name == MANIFEST else
                     next((limit for pattern, limit in LIMITS if pattern.fullmatch(name)), 0))
            if encrypted.is_symlink() or not encrypted.is_file() or name == path or not limit:
                raise ValueError("Unexpected encrypted snapshot entry")
            if encrypted.stat().st_size > limit + limit // 4096 + 4096:
                raise ValueError("Encrypted snapshot entry is too large")
            target = plain / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                subprocess.run([age, "-d", "-i", str(identity), str(encrypted)],
                               stdout=output, check=True, timeout=600)
            if not 0 < target.stat().st_size <= limit:
                raise ValueError("Invalid decrypted snapshot entry size")
            with target.open("rb") as content:
                if name == MANIFEST:
                    manifest = verify_manifest(target, signers, not_before, allow_legacy, not_after)
                else:
                    files[name] = {"size": target.stat().st_size, "sha256": hashlib.file_digest(content, "sha256").hexdigest()}
        if "vault.sqlite3" not in files or manifest != files:
            raise ValueError("Restored files did not match the manifest")
        (plain / MANIFEST).unlink()
        plain.rename(destination)
        return len(files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sealed", action="store_true")
    mode.add_argument("--restore", action="store_true")
    mode.add_argument("--restore-tar", action="store_true")
    parser.add_argument("--signers", type=Path)
    parser.add_argument("--not-before", type=int, help="Independently chosen earliest capture time, in Unix seconds")
    parser.add_argument("--allow-legacy-unsigned", action="store_true")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("identity", type=Path, nargs="?")
    args = parser.parse_args()
    if args.restore or args.restore_tar:
        if args.identity is None or (args.allow_legacy_unsigned
            and (args.signers is not None or args.not_before is not None)) or (
                not args.allow_legacy_unsigned and (args.signers is None or args.not_before is None)):
            parser.error("Restore requires an identity and --signers with --not-before, or explicit --allow-legacy-unsigned")
    elif args.identity or args.signers or args.not_before is not None or args.allow_legacy_unsigned:
        parser.error("Restore options require --restore or --restore-tar")
    os.umask(0o077)
    try:
        options = dict(signers=args.signers, not_before=args.not_before, allow_legacy=args.allow_legacy_unsigned)
        if args.restore_tar:
            with tempfile.TemporaryDirectory(prefix=".voltura-sealed-", dir=args.destination.parent) as temp:
                stage = Path(temp)
                with args.source.open("rb") as source:
                    extract_snapshot(source, stage)
                count = restore(stage / "snapshot", args.destination, args.identity, **options)
        elif args.restore:
            count = restore(args.source, args.destination, args.identity, **options)
        else:
            count = verify_and_extract(args.source, args.destination, sealed=args.sealed)
    except (OSError, ValueError, TypeError, tarfile.TarError, subprocess.SubprocessError):
        sys.exit("Vault snapshot validation failed. No backup was published.")
    print(f"Verified {count} files in the Vault snapshot.")
