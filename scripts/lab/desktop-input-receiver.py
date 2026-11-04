"""Disposable Xterm input sink: record one line, never execute keyboard input."""
import os
from pathlib import Path
import re
import sys

name = sys.argv[1]
if not re.fullmatch(r"desktop-input-[0-9]+\.txt", name):
    raise SystemExit("Invalid lab fixture filename")
target = Path("/home/vincent.linux/meshcentral-lab/acceptance") / name
print("MeshCentral disposable desktop input test. Type the marker, then Enter.", flush=True)
line = sys.stdin.readline()
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as output:
    output.write(line)
    output.flush()
    os.fsync(output.fileno())
print("Input captured. This program never executes shell commands.", flush=True)
sys.stdin.readline()
