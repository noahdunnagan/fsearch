#!/usr/bin/env python3
"""Run with python3 tests/test_tui.py; pure rendering/path safety, no desktop launched."""

import os
from pathlib import Path
import re
import runpy
import tempfile

ui = runpy.run_path(str(Path(__file__).resolve().parents[1] / "fsearch-desktop"))
ansi = re.compile(r"\x1b\[[0-9;]*m")

with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "quote'\" tab\t newline\n $(touch SHOULD_NOT_EXIST).pdf"
    path.write_text("real metadata fixture\n")
    stat = path.stat()
    hit = {"path": str(path), "kind": "file", "size": stat.st_size, "mtime": int(stat.st_mtime), "score": 1}
    token = ui["encode_hit"](hit)
    assert ui["open_target"](token) == str(path)
    assert ui["open_target"](token, True) == directory
    escaped = ui["safe_text"](str(path))
    assert "\\t" in escaped and "\\n" in escaped and "\n" not in escaped and "\t" not in escaped
    assert ui["safe_text"]("\x1b[31m\u202e") == r"\u001b[31m\u202e"
    for width in (42, 80, 120):
        records = list(ui["result_records"]({"ok": True, "hits": [hit]}, "modified-desc", width))
        payload, display = records[2].split("\t", 1)
        assert ui["decode_hit"](payload)["path"] == str(path)
        plain = ansi.sub("", display)
        assert "\x1b" not in plain and "\t" not in plain
        assert all(ui["cells"](line) <= max(24, width - 8) for line in plain.splitlines())
    assert ui["cells"](ui["fit"]("数学 café", 6)) == 6

print("TUI renderer/path checks passed")
