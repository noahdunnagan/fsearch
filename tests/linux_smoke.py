#!/usr/bin/env python3
"""Check the installed Linux daemon: python3 tests/linux_smoke.py [--restart].

--restart also checks offline changes (requires cached sudo authorization).
"""
import base64
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import termios
import time

home = Path.home()
data = Path(os.environ.get("XDG_DATA_HOME", home / ".local/share")) / "fsearch"


def request(value):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(30)
        conn.connect(str(data / "fsearch.sock"))
        conn.sendall(json.dumps(value).encode() + b"\n")
        with conn.makefile("rb") as response:
            result = json.loads(response.readline())
    assert result.get("ok"), result
    return result


def eventually(check, label, seconds=180):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if check():
                print("PASS:", label, flush=True)
                return
        except (AssertionError, OSError):
            pass
        time.sleep(0.2)
    raise AssertionError("timed out: " + label)


def paths(root):
    return {hit["path"] for hit in request({"q": "", "in": str(root), "limit": 200})["hits"]}


def content(root, marker):
    return {file["path"] for file in request({"op": "grep", "pattern": marker, "in": str(root)})["files"]}

def first_picker_row(root, file):
    """First reload must fit the real TTY even while fzf reports zero columns."""
    pid, fd = pty.fork()
    if pid == 0:
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 36, 128, 0, 0))
        os.environ["FZF_COLUMNS"] = "0"
        helper = Path(__file__).resolve().parents[1] / "fsearch-desktop"
        os.execv(sys.executable, [sys.executable, str(helper), "--results", "--query", f"in:{root}"])
    output = bytearray()
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
        else:
            raise AssertionError("picker reload timed out")
        _, status = os.waitpid(pid, 0)
        pid = 0
        assert os.waitstatus_to_exitcode(status) == 0
        for record in output.decode().split("\0"):
            token, _, row = record.partition("\t")
            if not row or token == "-":
                continue
            hit = json.loads(base64.urlsafe_b64decode(token))
            if hit["path"] == str(file):
                plain = re.sub(r"\x1b\[[0-9;]*m", "", row)
                assert "\n" not in plain and file.name in plain
                assert time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(file.stat().st_mtime)) in plain
                print("PASS: first picker reload shows inline name and modification date", flush=True)
                return
        raise AssertionError("picker did not render the indexed fixture")
    finally:
        if pid:
            try:
                os.kill(pid, 15)
            except ProcessLookupError:
                pass
            os.waitpid(pid, 0)
        os.close(fd)


root = Path(tempfile.mkdtemp(prefix=".fsearch-smoke-", dir=home))
service = f"fsearch-{os.getuid()}.service"
stopped = False
try:
    first = root / "fsearch live café.txt"
    first.write_text("FSearchLinuxSmokeBefore\n")
    eventually(lambda: str(first) in paths(root), "live file creation")
    eventually(lambda: str(first) in content(root, "FSearchLinuxSmokeBefore"), "indexed content creation")
    first_picker_row(root, first)
    original = first.stat()
    first.write_text("FSearchLinuxSmokeAfterX\n")
    assert first.stat().st_size == original.st_size
    os.utime(first, ns=(original.st_atime_ns, original.st_mtime_ns))
    eventually(lambda: str(first) in content(root, "FSearchLinuxSmokeAfterX") and str(first) not in content(root, "FSearchLinuxSmokeBefore"), "equal-size content update with restored mtime")
    victim = os.open(first, os.O_RDWR)
    try:
        replacement = root / "replacement.txt"
        replacement.write_text("FSearchAtomicReplacement\n")
        os.replace(replacement, first)
        os.write(victim, b"FSearchDetachedVictim\n")
        os.fchmod(victim, 0o600)
    finally:
        os.close(victim)
    eventually(lambda: str(first) in content(root, "FSearchAtomicReplacement") and not content(root, "FSearchDetachedVictim") and not content(root, "FSearchLinuxSmokeAfterX"), "atomic replacement and detached victim writes")
    os.chmod(first, 0o000)
    try:
        eventually(lambda: str(first) not in content(root, "FSearchAtomicReplacement"), "file permission revocation removes indexed content")
    finally:
        os.chmod(first, 0o600)
    eventually(lambda: str(first) in content(root, "FSearchAtomicReplacement"), "file permission restoration reindexes content")
    renamed = root / "renamed.txt"
    first.rename(renamed)
    eventually(lambda: str(renamed) in paths(root) and str(first) not in paths(root), "file rename removes old path")
    nested = root / "tree/inner"
    nested.mkdir(parents=True)
    leaf = nested / "leaf.txt"
    leaf.write_text("FSearchLinuxNestedMarker\n")
    eventually(lambda: str(leaf) in paths(root), "new nested directories")
    os.chmod(root / "tree", 0o000)
    try:
        eventually(lambda: str(leaf) not in paths(root), "permission revocation removes inaccessible descendants")
    finally:
        os.chmod(root / "tree", 0o700)
    eventually(lambda: str(leaf) in paths(root), "permission restoration reindexes descendants")
    moved = root / "moved"
    (root / "tree").rename(moved)
    moved_leaf = moved / "inner/leaf.txt"
    eventually(lambda: str(moved_leaf) in paths(root) and str(leaf) not in paths(root), "directory rename updates descendants")
    shutil.rmtree(moved)
    renamed.unlink()
    eventually(lambda: str(moved_leaf) not in paths(root) and str(renamed) not in paths(root), "file and subtree deletion")
    if "--restart" in sys.argv:
        offline = root / "offline.txt"
        offline.write_text("FSearchLinuxOfflineBefore\n")
        eventually(lambda: str(offline) in paths(root), "pre-restart file indexed")
        preserved = root / "preserved.txt"
        preserved.write_text("FSearchOfflineStampBefore\n")
        eventually(lambda: str(preserved) in content(root, "FSearchOfflineStampBefore"), "pre-restart content indexed")
        preserved_times = preserved.stat()
        old_index = (data / "index.bin").stat().st_mtime_ns
        request({"op": "save"})
        eventually(lambda: (data / "index.bin").stat().st_mtime_ns != old_index, "persistent index save")
        subprocess.run(["sudo", "-n", "systemctl", "stop", service], check=True)
        stopped = True
        directory_times = root.stat()
        offline.unlink()
        replacement = root / "offline-replacement.txt"
        replacement.write_text("FSearchLinuxOfflineAfter\n")
        preserved.write_text("FSearchOfflineStampAfterX\n")
        assert preserved.stat().st_size == preserved_times.st_size
        os.utime(preserved, ns=(preserved_times.st_atime_ns, preserved_times.st_mtime_ns))
        os.utime(root, ns=(directory_times.st_atime_ns, directory_times.st_mtime_ns))
        subprocess.run(["sudo", "-n", "systemctl", "start", service], check=True)
        stopped = False
        eventually(lambda: str(replacement) in paths(root) and str(offline) not in paths(root), "offline changes reconcile despite restored directory mtime", 300)
        eventually(lambda: str(replacement) in content(root, "FSearchLinuxOfflineAfter") and str(offline) not in content(root, "FSearchLinuxOfflineBefore"), "offline content reconciliation", 300)
        eventually(lambda: str(preserved) in content(root, "FSearchOfflineStampAfterX") and str(preserved) not in content(root, "FSearchOfflineStampBefore"), "offline equal-size content with restored mtime", 300)
finally:
    if stopped:
        subprocess.run(["sudo", "-n", "systemctl", "start", service], check=True)
    shutil.rmtree(root)
