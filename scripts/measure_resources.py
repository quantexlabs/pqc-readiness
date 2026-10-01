#!/usr/bin/env python3
"""Record whole-process fixture measurements; no larger-scale performance claim."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    commands = [
        [sys.executable, "scripts/regenerate_results.py", "--check"],
        [sys.executable, "-m", "pqc_readiness", "pipeline", "--skip-tls"],
    ]
    rows = []
    with tempfile.TemporaryDirectory() as temporary:
        commands[1].extend(["--output-dir", temporary])
        for command in commands:
            for repeat in range(3):
                start = time.perf_counter()
                proc = subprocess.Popen(
                    command, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                _, status, usage = os.wait4(proc.pid, 0)
                proc.returncode = os.waitstatus_to_exitcode(status)
                rows.append(
                    {
                        "command": ["python", *command[1:5]],
                        "repeat": repeat + 1,
                        "wall_seconds": time.perf_counter() - start,
                        "peak_rss_bytes": int(
                            usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
                        ),
                        "exit_code": proc.returncode,
                    }
                )
    receipt = {
        "scope": "three whole-process local fixture runs per command",
        "python": platform.python_version(),
        "os": platform.system(),
        "os_release": platform.release(),
        "machine": platform.machine(),
        "runs": rows,
    }
    path = ROOT / "state/evidence/r3/resources.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    return int(any(row["exit_code"] != 0 for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
