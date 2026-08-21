#!/usr/bin/env python3
"""Validate and run the deterministic active-probe regression contract."""
import argparse, hashlib, json, pathlib, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "scripts" / "active-probe-cases.json"

def sha(data): return hashlib.sha256(data).hexdigest()

def load(path):
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("schemaVersion") != 1: raise ValueError("schemaVersion must be 1")
    required, cases = value.get("requiredCases"), value.get("cases")
    if not isinstance(required, list) or not isinstance(cases, list): raise ValueError("case arrays missing")
    ids = [case.get("id") for case in cases]
    if len(ids) != len(set(ids)) or set(ids) != set(required) or len(ids) != len(required):
        raise ValueError("cases must cover requiredCases exactly once")
    for case in cases:
        if not all(isinstance(case.get(key), str) and case[key] for key in ("id", "test", "observation")):
            raise ValueError("each case requires id, test, and observation")
    for key in ("comparators", "timingPolicy", "packetizationPolicy"):
        if not value.get(key): raise ValueError(f"missing {key}")
    return value

def run(manifest_path, output):
    manifest, results = load(manifest_path), []
    for case in manifest["cases"]:
        command = ["cargo","test","--lib","--all-features","--locked",case["test"],"--","--exact"]
        started = time.monotonic_ns()
        done = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        executed = "running 1 test" in done.stdout
        exit_code = done.returncode if executed else 125
        results.append({"id":case["id"],"test":case["test"],"observation":case["observation"],
            "command":command,"executedExactlyOne":executed,"exitCode":exit_code,"elapsedNs":time.monotonic_ns()-started,
            "stdoutSha256":sha(done.stdout.encode()),"stderrSha256":sha(done.stderr.encode())})
        if exit_code:
            sys.stderr.write(done.stdout + done.stderr); break
    head = subprocess.check_output(["git","rev-parse","HEAD"],cwd=ROOT,text=True).strip()
    evidence={"schemaVersion":1,"gate":"active-probe-deterministic-cases","repositoryHead":head,
        "manifest":{"path":str(manifest_path),"sha256":sha(manifest_path.read_bytes())},
        "caseCount":len(results),"requiredCaseCount":len(manifest["requiredCases"]),"cases":results,
        "ok":len(results)==len(manifest["cases"]) and all(x["exitCode"]==0 for x in results)}
    output.parent.mkdir(parents=True,exist_ok=True)
    temporary=output.with_name("."+output.name+".tmp")
    temporary.write_text(json.dumps(evidence,indent=2)+"\n",encoding="utf-8"); temporary.replace(output)
    if not evidence["ok"]: raise SystemExit("active-probe deterministic gate failed")

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--manifest",type=pathlib.Path,default=DEFAULT_MANIFEST)
    parser.add_argument("--output",type=pathlib.Path); parser.add_argument("--check",action="store_true"); args=parser.parse_args()
    manifest=load(args.manifest.resolve())
    if args.check:
        listed=subprocess.check_output(
            ["cargo","test","--lib","--all-features","--locked","--","--list"],
            cwd=ROOT,text=True,stderr=subprocess.DEVNULL)
        available={line.removesuffix(": test") for line in listed.splitlines() if line.endswith(": test")}
        missing=sorted(case["test"] for case in manifest["cases"] if case["test"] not in available)
        if missing: raise SystemExit("active-probe tests missing:\n"+"\n".join(missing))
        print(f"active-probe manifest: PASS ({len(manifest['cases'])} cases)"); return
    if args.output is None: parser.error("--output is required unless --check is used")
    run(args.manifest.resolve(),args.output.resolve())
if __name__ == "__main__": main()
