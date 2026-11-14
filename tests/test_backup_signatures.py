"""Exercise signed restore with age and OpenSSH using disposable keys."""

import io
import runpy
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
EXPORT = runpy.run_path(str(SCRIPTS / "export-lenovo-backup.py"))["export"]
VERIFY = runpy.run_path(str(SCRIPTS / "verify-lenovo-backup.py"))
PULL = runpy.run_path(str(SCRIPTS / "run-nas-backup.py"))


class BackupSignatures(unittest.TestCase):
    def test_pull_stops_before_writing_over_limit(self):
        output = io.BytesIO()
        with self.assertRaises(PULL["BackupLimitError"]):
            PULL["pull_snapshot"]([sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes(2**20 + 1))"],
                                  output, limit=2**20)
        self.assertEqual(len(output.getvalue()), 2**20)

    def test_restore_tar_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp)
            source = io.BytesIO()
            with tarfile.open(fileobj=source, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                member = tarfile.TarInfo("snapshot/../vault.sqlite3.age")
                member.size = 1
                tar.addfile(member, io.BytesIO(b"X"))
            with self.assertRaisesRegex(ValueError, "entry size or path"):
                VERIFY["extract_snapshot"](source, stage)
            self.assertEqual(list(stage.iterdir()), [])

    def test_signed_backup_freshness_and_legacy_compatibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            identity = work / "age-key"
            subprocess.run(["age-keygen", "-o", str(identity)], check=True, stderr=subprocess.DEVNULL)
            recipient = subprocess.check_output(["age-keygen", "-y", str(identity)], text=True).strip()
            for name in ("lenovo", "other"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(work / name)], check=True)
            signers = work / "allowed-signers"
            signers.write_text("voltura-lenovo " + (work / "lenovo.pub").read_text(), encoding="ascii")
            with closing(sqlite3.connect(work / "vault.sqlite3")) as connection:
                connection.executescript("""
                    CREATE TABLE sessions (id TEXT);
                    INSERT INTO sessions VALUES ('disposable session');
                    CREATE TABLE files (object TEXT, size INTEGER, published INTEGER);
                """)
                object_id = "6c9812d0-6443-43be-955e-18cbd855b49c"
                connection.execute("INSERT INTO files VALUES (?, 0, 1)", (object_id,))
                connection.commit()
            blob = Path("vault.blobs") / object_id / "0"
            (work / blob).parent.mkdir(parents=True)
            (work / blob).write_bytes(b"A" * 17)
            cache = work / "cache"
            cache.mkdir()
            cutoff = int(time.time()) - 1
            for name, signer in (("signed", work / "lenovo"), ("forged", work / "other"), ("legacy", None)):
                stream = io.BytesIO()
                EXPORT(work, work / "published", stream, recipient, cache, "age", signing_key=signer)
                tar = work / (name + ".tar")
                tar.write_bytes(stream.getvalue())
                self.assertEqual(VERIFY["verify_and_extract"](tar, work / name, sealed=True), 2)

            def restore(name, destination, earliest=cutoff):
                return VERIFY["restore"](work / name, work / destination, identity,
                                         signers=signers, not_before=earliest)

            self.assertEqual(restore("signed", "verified"), 2)
            self.assertEqual((work / "verified" / blob).read_bytes(), b"A" * 17)
            wrapped = work / "nas-restore.tar"
            with tarfile.open(wrapped, "w", format=tarfile.USTAR_FORMAT) as archive:
                archive.add(work / "signed", arcname="snapshot")
            subprocess.run([sys.executable, str(SCRIPTS / "verify-lenovo-backup.py"), "--restore-tar",
                            "--signers", str(signers), "--not-before", str(cutoff),
                            str(wrapped), str(work / "nas-verified"), str(identity)], check=True)
            self.assertEqual((work / "nas-verified" / blob).read_bytes(), b"A" * 17)
            with closing(sqlite3.connect(work / "verified" / "vault.sqlite3")) as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM sessions").fetchone(), (0,))
            with self.assertRaisesRegex(ValueError, "outside the trusted window"):
                restore("signed", "stale", int(time.time()) + 1)
            with self.assertRaisesRegex(ValueError, 'outside the trusted window'):
                VERIFY['restore'](work / 'signed', work / 'outside-schedule', identity,
                                  signers=signers, not_before=cutoff, not_after=cutoff - 1)
            self.assertFalse((work / 'outside-schedule').exists())
            with self.assertRaises(subprocess.CalledProcessError):
                restore("forged", "wrong-signer")
            with self.assertRaisesRegex(ValueError, "Expected a signed manifest"):
                restore("legacy", "unsigned")
            for refused in ("stale", "wrong-signer", "unsigned"):
                self.assertFalse((work / refused).exists())
            self.assertEqual(VERIFY["restore"](work / "legacy", work / "legacy-verified", identity,
                                               allow_legacy=True), 2)
            replacement = work / "signed" / blob.with_suffix(".age")
            replacement.write_bytes(subprocess.check_output(["age", "-r", recipient], input=b"B" * 17))
            with self.assertRaisesRegex(ValueError, "did not match"):
                restore("signed", "substituted")
            self.assertFalse((work / "substituted").exists())

            with closing(sqlite3.connect(work / "vault.sqlite3")) as connection:
                connection.executescript("CREATE TABLE owner(singleton INTEGER, key_epoch INTEGER);"
                                         "INSERT INTO owner VALUES(1,2); PRAGMA user_version=8;"
                                         "CREATE TABLE sync_devices(verifier BLOB);"
                                         "CREATE TABLE used_sync_refreshes(verifier BLOB);")
                marker = b"synthetic device verifier bytes!"
                for table in ("sync_devices", "used_sync_refreshes"):
                    connection.execute(f"INSERT INTO {table} VALUES (?)", (marker,))
                connection.commit()
            rotated_blob = Path("vault.blobs") / "epoch-2" / object_id / "0"
            (work / rotated_blob).parent.mkdir(parents=True)
            (work / rotated_blob).write_bytes(b"B" * 17)
            stream = io.BytesIO()
            EXPORT(work, work / "published", stream, recipient, cache, "age", signing_key=work / "lenovo")
            tar = work / "rotated.tar"
            tar.write_bytes(stream.getvalue())
            self.assertEqual(VERIFY["verify_and_extract"](tar, work / "rotated", sealed=True), 2)
            self.assertEqual(restore("rotated", "rotated-verified"), 2)
            self.assertEqual((work / "rotated-verified" / rotated_blob).read_bytes(), b"B" * 17)
            self.assertFalse((work / "rotated-verified" / blob).exists())
            restored_db = work / "rotated-verified" / "vault.sqlite3"
            self.assertNotIn(marker, restored_db.read_bytes())
            with closing(sqlite3.connect(restored_db)) as connection:
                for table in ("sync_devices", "used_sync_refreshes"):
                    self.assertEqual(connection.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))


if __name__ == "__main__":
    unittest.main()
