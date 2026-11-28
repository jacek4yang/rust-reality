#!/usr/bin/env bash
# Digest-checked fallback when download-artifact reports success without
# finishing (empty download-path). Fail closed on a missing digest, a
# digest mismatch, or a missing archive. No qualification verdict change.
# Exit 0 with an empty download-path on fallback failure so the finish step
# emits the fail-closed error; do not turn a restore flake into a missing-file
# exception that could be misread.
set -euo pipefail
: "${ARTIFACT_NAME:?}" "${STAGE:?}" "${GH_TOKEN:?}"
: "${GITHUB_REPOSITORY:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_API_URL:?}"

dest="$STAGE/try"
rm -rf "$dest"
mkdir -p "$dest"

python3 - "$dest" <<'PY'
import hashlib, json, os, ssl, sys, urllib.request, zipfile
from pathlib import Path

name = os.environ["ARTIFACT_NAME"]
token = os.environ["GH_TOKEN"]
repo = os.environ["GITHUB_REPOSITORY"]
run_id = os.environ["GITHUB_RUN_ID"]
api = os.environ["GITHUB_API_URL"].rstrip("/")
dest = Path(sys.argv[1])
zip_path = dest.parent / "artifact.zip"

def api_request(url, dest_file=None):
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "rust-reality-restore-named-artifact",
        },
    )
    with urllib.request.urlopen(req, context=ssl.create_default_context()) as resp:
        data = resp.read()
    if dest_file is not None:
        dest_file.write_bytes(data)
        return None
    return json.loads(data.decode())

def fail(msg):
    print(f"::error::artifact restore {name}: {msg}", file=sys.stderr)
    sys.exit(0)

art = None
page = 1
while page <= 20:
    body = api_request(
        f"{api}/repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
    )
    arts = body.get("artifacts") or []
    for item in arts:
        if item.get("name") == name and not item.get("expired"):
            art = item
            break
    if art is not None or len(arts) < 100:
        break
    page += 1
if art is None:
    fail(f"gh fallback could not find an unexpired artifact on run {run_id}")

digest = art.get("digest") or ""
if not digest.startswith("sha256:") or len(digest) != len("sha256:") + 64:
    fail("gh fallback refused to extract without a sha256 digest from the API")
expected = digest[len("sha256:"):]

api_request(
    f"{api}/repos/{repo}/actions/artifacts/{art['id']}/zip",
    dest_file=zip_path,
)
actual = hashlib.sha256(zip_path.read_bytes()).hexdigest()
if actual != expected:
    zip_path.unlink(missing_ok=True)
    fail(f"gh fallback digest mismatch (expected sha256:{expected}, got sha256:{actual})")

with zipfile.ZipFile(zip_path) as zf:
    for info in zf.infolist():
        parts = Path(info.filename).parts
        if info.filename.startswith("/") or ".." in parts:
            zip_path.unlink(missing_ok=True)
            fail(f"gh fallback refused escaped zip path {info.filename!r}")
    zf.extractall(dest)
zip_path.unlink(missing_ok=True)
if not any(dest.iterdir()):
    fail("gh fallback extracted no files")

out = os.environ.get("GITHUB_OUTPUT")
if not out:
    fail("GITHUB_OUTPUT is unset")
with open(out, "a", encoding="utf-8") as fh:
    fh.write(f"download-path={dest}\n")
print(f"artifact restore {name}: gh fallback completed with verified sha256:{expected}")
PY
