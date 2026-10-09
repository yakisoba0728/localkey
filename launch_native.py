"""Launch the signed native HID app with this project's isolated state paths."""

import argparse
import json
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--backend", choices=["software", "auto", "se"], default="software")
args = parser.parse_args()
project = Path(__file__).resolve().parent
workspace = project.parent.parent if project.parent.name == "outputs" else project
state = workspace / "work/native-swpasskey"
state.mkdir(parents=True, exist_ok=True)
app = project / "prebuilt/swpasskeyd.app"
control = app / "Contents/MacOS/swpasskeyctl"
socket = state / "ctl.sock"


def status():
    try:
        response = subprocess.run(
            [str(control), "--socket", str(socket), "stats"],
            capture_output=True, text=True, timeout=3,
        )
        if response.returncode == 0:
            value = json.loads(response.stdout)
            if value.get("ok"):
                return value
    except (subprocess.TimeoutExpired, ValueError):
        pass
    return None


current = status()
if current:
    print(f"Native authenticator already running; backend={current['key_backend']}")
    print("Quit it from the key menu before changing the key backend.")
else:
    subprocess.run([
        "/usr/bin/open", "-n", "-a", str(app),
        "--stdout", str(state / "app-out.log"),
        "--stderr", str(state / "app-err.log"),
        "--env", "SWPASSKEY_LOG=info", "--args",
        "--key-backend=" + args.backend, "--dek-file",
        "--store", str(state / "credentials.bin"),
        "--ctl-socket", str(socket),
    ], check=True)
    for _ in range(20):
        current = status()
        if current:
            print(f"Native authenticator running; backend={current['key_backend']}")
            break
        time.sleep(0.25)
    else:
        print("App did not expose its control socket. Check macOS permissions and app-err.log.")
        raise SystemExit(1)
print(f"State directory: {state}")
