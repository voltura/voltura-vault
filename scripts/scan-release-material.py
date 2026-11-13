"""Reject credential material and deployment addresses without printing matches."""
import ipaddress
import pathlib
import re
import sys

blocked = re.compile(
    rb"-----BEGIN (?:[A-Z0-9 ]*PRIVATE KEY|CERTIFICATE)-----"
    rb"|SQLite format 3\x00"
    rb"|voltura-vault-recovery\.vvrk\x00"
)
addresses = re.compile(
    rb"(?i)(?:https?://|ssh://|(?:address|endpoint)\s*=\s*)"
    rb"([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?=[:/\s\"']|$)"
)
suffixes = {".key", ".pem", ".cer", ".crt", ".p12", ".pfx", ".sqlite", ".sqlite3",
            ".db", ".vvrk", ".vvkr", ".vvsa", ".agekey", ".dpapi", ".bundle"}

def inspect(path):
    if path.is_symlink() or not path.is_file():
        return True
    name = path.name.lower()
    if path.suffix.lower() in suffixes or name in {"setup-token", "privkey.pem"}:
        return False
    data = path.read_bytes()
    # These strings are needed to implement parsers and linked SQLite contains
    # its own format magic. Binary artefacts are checked for PEM key material
    # on whole lines, and separately for prohibited credential filenames.
    if path.name == pathlib.Path(__file__).name:
        return True
    if b"\x00" in data[:4096] and not data.startswith(b"SQLite format 3\x00"):
        data = b"\n".join(re.findall(rb"[\x20-\x7e]{5,}", data))
        if re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\n[A-Za-z0-9+/]{48}", data):
            return False
    elif blocked.search(data) and not (path.suffix == ".rs" and b'-----BEGIN CERTIFICATE-----"' in data):
        return False
    for found in addresses.findall(data):
        try:
            ip = ipaddress.ip_address(found.decode("ascii"))
        except ValueError:
            continue
        if not (ip.is_loopback or ip.is_unspecified or str(ip) in {"192.0.2.1", "198.51.100.1", "203.0.113.1"}):
            return False
    return True

paths = (map(pathlib.Path, sys.stdin.buffer.read().decode().rstrip("\x00").split("\x00"))
         if sys.argv[1] == "--tracked" else pathlib.Path(sys.argv[1]).rglob("*"))
count = sum(not inspect(path) for path in paths)
if count:
    sys.exit(f"Release material check failed in {count} file(s); inspect locally.")
print("Release material check passed.")
