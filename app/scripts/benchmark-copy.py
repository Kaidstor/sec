import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import uuid

if sys.platform != "darwin":
    raise SystemExit("native clipboard benchmark requires macOS")

repo = pathlib.Path(__file__).resolve().parents[2]
work = pathlib.Path(tempfile.mkdtemp(prefix="sec-native-copy-"))
try:
    source = repo / "cli/internal/command/input_unix.go"
    original = source.read_text()
    target = "$.NSPasteboard.generalPasteboard"
    if original.count(target) != 1:
        raise RuntimeError("clipboard isolation overlay no longer matches source")
    board = "org.kaidstor.sec.perf." + uuid.uuid4().hex
    patched = work / "input_unix.go"
    patched.write_text(original.replace(target, "$.NSPasteboard.pasteboardWithName(" + json.dumps(board) + ")"))
    overlay = work / "overlay.json"
    overlay.write_text(json.dumps({"Replace": {str(source): str(patched)}}))
    binary = work / "sec"
    subprocess.run(["go", "build", "-overlay", str(overlay), "-o", str(binary), "."], cwd=repo / "cli", check=True)
    env = os.environ.copy()
    env.update(SEC_KEY=os.urandom(32).hex(), SEC_STORE=str(work / "store.enc"),
               SEC_KEY_FILE=str(work / "unused-key"), XDG_CONFIG_HOME=str(work / "config"),
               XDG_DATA_HOME=str(work / "data"), SEC_NO_SKILL_SYNC="1", SEC_NO_USAGE="1",
               SEC_NATIVE_BENCH_CLI=str(binary), SEC_NATIVE_BENCH_BOARD=board)
    subprocess.run([str(binary), "set", "perf/EXAMPLE"], input="synthetic-clipboard-measurement",
                   env=env, capture_output=True, text=True, check=True)
    result = subprocess.run(["cargo", "test", "--lib", "native_clipboard::tests::benchmark_native_against_cli_clipboard",
                             "--", "--ignored", "--nocapture"], cwd=repo / "app/src-tauri", env=env)
    raise SystemExit(result.returncode)
finally:
    shutil.rmtree(work)
