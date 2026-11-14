"""Pull an encrypted Vault snapshot over SSH and save it in the local restic repository."""

import os
import contextlib
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

MAX_ARCHIVE_BYTES = 8 * 1024**3


class BackupLimitError(ValueError):
    pass


def pull_snapshot(command, output, timeout=1200, limit=MAX_ARCHIVE_BYTES):
    with subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=sys.stderr) as process:
        expired = threading.Event()

        def stop():
            expired.set()
            if process.poll() is None:
                process.kill()

        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            size = 0
            while block := process.stdout.read(1024 * 1024):
                size += len(block)
                if size > limit:
                    raise BackupLimitError("Snapshot exceeds the 8 GiB backup size limit.")
                output.write(block)
            status = process.wait()
            if expired.is_set():
                raise subprocess.TimeoutExpired(command, timeout)
            if status:
                raise subprocess.CalledProcessError(status, command)
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
            timer.join()


def run(root):
    restic = [str(root / "restic.exe"), "-r", str(root / "sealed-repository"),
              "--insecure-no-password"]
    ssh = Path(os.environ["SystemRoot"]) / "System32/OpenSSH/ssh.exe"
    pull = [
        str(ssh), "-v", "-F", "none", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3",
        "-o", "UserKnownHostsFile=" + (root / "known_hosts").as_posix(),
        "-o", "HostKeyAlgorithms=ssh-ed25519", "-i", str(root / "backup-ed25519"),
        "voltura-backup@vault.example.test",
    ]
    with tempfile.TemporaryDirectory(prefix=".pull-", dir=root) as temporary:
        stage = Path(temporary)
        archive = stage / "snapshot.tar"
        if shutil.disk_usage(stage).free < 2 * MAX_ARCHIVE_BYTES:
            raise BackupLimitError("Backup needs at least 16 GiB of free staging space.")
        with archive.open("xb") as output:
            pull_snapshot(pull, output)
        subprocess.run(
            [sys.executable, "-I", str(root / "verify-lenovo-backup.py"), "--sealed", str(archive), str(stage / "snapshot")],
            check=True, timeout=1200, stdout=sys.stdout, stderr=sys.stderr,
        )
        subprocess.run(restic + ["backup", "--host", "vault-backup", "--tag", "voltura-vault", "snapshot"],
                       cwd=stage, check=True, timeout=1200, stdout=sys.stdout, stderr=sys.stderr)

    now = datetime.now(timezone.utc)
    (root / "last-success.txt").write_text(now.isoformat() + "\n", encoding="ascii")
    checked = root / "last-sealed-repository-check.txt"
    last_check = datetime.fromisoformat(checked.read_text(encoding="ascii").strip()) if checked.exists() else None
    if last_check is None or now - last_check >= timedelta(days=7):
        subprocess.run(restic + ["check"], check=True, timeout=1800, stdout=sys.stdout, stderr=sys.stderr)
        subprocess.run(restic + ["forget", "--keep-within", "365d", "--tag", "voltura-vault", "--prune"],
                       check=True, timeout=1800, stdout=sys.stdout, stderr=sys.stderr)
        checked.write_text(now.isoformat() + "\n", encoding="ascii")


if __name__ == "__main__":
    backup_root = Path(__file__).resolve().parent
    with (backup_root / "last-run.log").open("w", encoding="utf-8", buffering=1) as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                run(backup_root)
            except subprocess.CalledProcessError as error:
                print(f"{Path(error.cmd[0]).name} exited with code {error.returncode}.", file=log)
                sys.exit(1)
            except BackupLimitError as error:
                print(str(error), file=log)
                sys.exit(1)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                print(f"Vault backup or repository maintenance failed ({type(error).__name__}).", file=log)
                sys.exit(1)
