#!/usr/bin/env bash
# TenetX Devin Cloud canary probe (written by tests/human_qa/devin_cloud/live_cloud_canary.py).
# Usage: bash canary/tenetx_probe.sh CONTROL_PLANE_URL ORG
# Prints one TENETX_* line per check. Never prints a secret or a path.
set -u
exec python3 - "$@" <<'PY'
import base64, hashlib, json, os, secrets, shutil, subprocess, sys, tempfile

FILES = ('.claude-plugin/plugin.json', '.devin-plugin/plugin.json', 'hooks.json', 'hooks/tenetx_devin_hook.py', 'hooks/tenetx_devin_screen.py')
HOOK = "hooks/tenetx_devin_hook.py"
SKIP = {"node_modules", ".git", "proc", "sys", "dev"}


def plugin_roots():
    # Every directory holding the plugin's hook, nearest install locations first.
    home = os.path.expanduser("~")
    bases = [os.environ.get(k, "") for k in ("CLAUDE_PLUGIN_ROOT", "DEVIN_PLUGIN_ROOT", "PLUGIN_ROOT")]
    bases += [os.path.join(home, ".devin"), os.path.join(home, ".config", "devin"), home, "/opt", "/usr/local", "/etc"]
    found = []
    for base in bases:
        if not base or not os.path.isdir(base):
            continue
        floor = base.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = [] if dirpath.count("/") - floor >= 6 else [d for d in dirnames if d not in SKIP]
            if os.path.basename(dirpath) == "hooks" and "tenetx_devin_hook.py" in filenames:
                root = os.path.realpath(os.path.dirname(dirpath))
                if root not in found:
                    found.append(root)
    return found


def sha(path):
    try:
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except OSError:
        return "missing"


roots = plugin_roots()
print("TENETX_PLUGIN roots=%d" % len(roots))
root = roots[0] if roots else ""
for name in FILES:
    print("TENETX_PLUGIN_FILE name=%s sha256=%s" % (name, sha(os.path.join(root, name)) if root else "missing"))

pin = {}
try:
    with open(os.path.expanduser("~/.tenetx/cache/tenetx-windsurf-guard.py.pin")) as handle:
        pin = json.load(handle)
except Exception:
    pass
print("TENETX_GUARD version=%s sha256=%s" % (pin.get("version", ""), pin.get("sha256", "")))

DROP = ("TENETX_DEVIN_TOKEN", "TENETX_URL", "TENETX_ORG", "TENETX_VMCP_TOKEN", "TENETX_VMCP_TOKEN_FILE",
        "TENETX_FAIL_MODE", "TENETX_DEVIN_PLUGIN_CACHE", "TENETX_DEVIN_PLUGIN_TOKEN_FILE",
        "TENETX_VMCP_SENDER_KEY_FILE", "TENETX_VMCP_SENDER_KEY_ID")
EVENT = b'{"hook_event_name":"SessionStart","session_id":"tenetx-canary-negative"}'


def negative(name, packed):
    if not root:
        print("TENETX_NEG %s rc=-1 reason=plugin_not_found status=none" % name)
        return
    home = tempfile.mkdtemp(prefix="tenetx-canary-home.")
    env = {k: v for k, v in os.environ.items() if k not in DROP}
    # An empty home and no token file: the hook sees only what this case passes.
    env.update(HOME=home, TENETX_DEVIN_PLUGIN_TOKEN_FILE=os.path.join(home, "no-token"))
    if packed:
        env["TENETX_DEVIN_TOKEN"] = packed
    try:
        rc = subprocess.run([sys.executable, "-I", os.path.join(root, HOOK)], input=EVENT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60).returncode
    except Exception:
        rc = -2
    reason, status = "none", "none"
    try:
        with open(os.path.join(home, ".tenetx", "capture_failures.jsonl")) as handle:
            for line in handle:
                record = json.loads(line)
                reason = record.get("reason", reason)
                if record.get("reason") == "guard_download_failed":
                    status = str(record.get("status", "none"))
    except Exception:
        pass
    shutil.rmtree(home, ignore_errors=True)
    print("TENETX_NEG %s rc=%d reason=%s status=%s" % (name, rc, reason, status))


negative("missing", "")
# The right control plane and org with a bearer it never issued. The empty home
# forces the signed guard download, which the control plane must refuse with 401/403.
url, org = (sys.argv[1:3] + ["", ""])[:2]
if url and org:
    body = json.dumps({"o": org, "t": "forged-" + secrets.token_hex(16), "u": url},
                      separators=(",", ":"), sort_keys=True).encode()
    negative("forged", "txdc1." + base64.urlsafe_b64encode(body).decode().rstrip("="))
else:
    print("TENETX_NEG forged rc=-1 reason=no_control_plane status=none")
PY
