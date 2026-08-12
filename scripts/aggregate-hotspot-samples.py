#!/usr/bin/env python3
"""Map identity-pinned perf symbol offsets onto exact IDA instructions."""

import argparse
import bisect
import json
import re
import sys
import tempfile
from pathlib import Path


def fail(message: str) -> "NoReturn":
    raise SystemExit(message)


def parse_sample_headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    for line in lines:
        if not line.startswith("# ") or "=" not in line:
            continue
        key, value = line[2:].split("=", 1)
        headers[key] = value
    return headers


def aggregate(
    bundle: Path,
    max_unmapped_period_percent: float,
    unmapped_period_explanation: str | None = None,
) -> dict:
    summary_path = bundle / "ida" / "summary.json"
    disassembly_path = bundle / "ida" / "disassembly.json"
    samples_path = bundle / "perf-symbol-samples.txt"
    for path in (summary_path, disassembly_path, samples_path):
        if not path.is_file():
            fail(f"missing input file: {path}")

    outputs = [
        bundle / "instruction-hotspots.json",
        bundle / "instruction-hotspots.tsv",
        bundle / "instruction-hotspots.txt",
    ]
    existing = [str(path) for path in outputs if path.exists()]
    if existing:
        fail("refusing to overwrite aggregate output: " + ", ".join(existing))

    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    raw_instructions = json.loads(disassembly_path.read_text(encoding="utf-8"))
    sample_lines = samples_path.read_text(encoding="utf-8").splitlines()
    headers = parse_sample_headers(sample_lines)
    for key in ("binary_sha256", "binary_build_id", "raw_symbol", "dso_basename"):
        if not headers.get(key):
            fail(f"sample file is missing identity header: {key}")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", headers["binary_sha256"]):
        fail("sample binary SHA-256 is malformed")
    if not re.fullmatch(r"[0-9a-fA-F]+", headers["binary_build_id"]):
        fail("sample binary build ID is malformed")
    if summary.get("inputSha256") != headers["binary_sha256"]:
        fail("IDA input SHA-256 does not match perf sample identity")

    function = summary["function"]
    function_start = int(function["start"], 0)
    function_end = int(function["end"], 0)
    if function_end <= function_start:
        fail("invalid IDA function range")
    if function["name"] != headers["raw_symbol"]:
        fail("IDA raw symbol does not match perf sample identity")

    instructions = []
    for raw in raw_instructions:
        address = int(raw["address"], 0)
        size = int(raw["size"])
        if size <= 0 or not function_start <= address < function_end:
            fail(f"invalid instruction at {raw['address']}")
        instructions.append(
            {
                "addressValue": address,
                "address": f"0x{address:x}",
                "offset": f"0x{address - function_start:x}",
                "size": size,
                "bytes": raw["bytes"],
                "text": raw["text"],
                "sampleCount": 0,
                "periodSum": 0,
            }
        )
    instructions.sort(key=lambda item: item["addressValue"])
    if len(instructions) != int(function["instructionCount"]):
        fail("instruction count differs from IDA summary")
    for previous, current in zip(instructions, instructions[1:]):
        if previous["addressValue"] + previous["size"] > current["addressValue"]:
            fail("IDA instruction ranges overlap")

    starts = [item["addressValue"] for item in instructions]
    totals = {
        "sampleRows": 0,
        "periodSum": 0,
        "mappedRows": 0,
        "mappedPeriod": 0,
        "unmappedRows": 0,
        "unmappedPeriod": 0,
    }
    offset_pattern = re.compile(r"\+0x([0-9a-fA-F]+)$")
    expected_symbol = headers["raw_symbol"]
    expected_dso = headers["dso_basename"]

    for line_number, raw_line in enumerate(sample_lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=3)
        if len(parts) != 4:
            fail(f"invalid perf sample at {samples_path}:{line_number}: {line}")
        try:
            period = int(parts[0], 10)
        except ValueError as error:
            fail(f"invalid period at {samples_path}:{line_number}: {error}")
        if period <= 0:
            fail(f"non-positive period at {samples_path}:{line_number}")
        match = offset_pattern.search(parts[2])
        symbol = parts[2][: match.start()] if match else ""
        dso = Path(parts[3].strip().strip("()[]")).name
        if match is None or symbol != expected_symbol or dso != expected_dso:
            fail(f"sample identity mismatch at {samples_path}:{line_number}")

        sampled_address = function_start + int(match.group(1), 16)
        totals["sampleRows"] += 1
        totals["periodSum"] += period
        index = bisect.bisect_right(starts, sampled_address) - 1
        mapped = False
        if index >= 0:
            instruction = instructions[index]
            instruction_end = instruction["addressValue"] + instruction["size"]
            mapped = (
                function_start <= sampled_address < function_end
                and instruction["addressValue"] <= sampled_address < instruction_end
            )
        if mapped:
            instruction["sampleCount"] += 1
            instruction["periodSum"] += period
            totals["mappedRows"] += 1
            totals["mappedPeriod"] += period
        else:
            totals["unmappedRows"] += 1
            totals["unmappedPeriod"] += period

    if totals["sampleRows"] == 0 or totals["mappedRows"] == 0:
        fail("perf sample file contains no mapped samples")
    unmapped_percent = totals["unmappedPeriod"] * 100.0 / totals["periodSum"]
    totals["unmappedPeriodPercent"] = unmapped_percent
    if unmapped_percent >= 1.0:
        fail(
            f"unmapped perf period {unmapped_percent:.6f}% is not below the 1% hard gate"
        )
    if unmapped_percent > max_unmapped_period_percent:
        if not unmapped_period_explanation or not unmapped_period_explanation.strip():
            fail(
                f"unmapped perf period {unmapped_percent:.6f}% exceeds the zero-default "
                "gate; pass --unmapped-period-explanation for a reviewed sub-1% exception"
            )

    sampled = []
    for instruction in instructions:
        if not instruction["sampleCount"]:
            continue
        instruction["samplePercent"] = (
            instruction["sampleCount"] * 100.0 / totals["mappedRows"]
        )
        instruction["periodPercent"] = (
            instruction["periodSum"] * 100.0 / totals["mappedPeriod"]
        )
        sampled.append(instruction)
    sampled.sort(
        key=lambda item: (item["periodSum"], item["sampleCount"], -item["addressValue"]),
        reverse=True,
    )
    for rank, instruction in enumerate(sampled, start=1):
        instruction["rank"] = rank
        del instruction["addressValue"]

    report = {
        "schemaVersion": 1,
        "identity": headers,
        "mappingGate": {
            "maxUnmappedPeriodPercent": max_unmapped_period_percent,
            "hardMaximumPercentExclusive": 1.0,
            "unmappedPeriodExplanation": unmapped_period_explanation,
        },
        "function": {
            "name": function["name"],
            "start": function["start"],
            "end": function["end"],
            "size": function_end - function_start,
            "instructionCount": len(instructions),
            "sampledInstructionCount": len(sampled),
        },
        "totals": totals,
        "instructions": sampled,
    }
    outputs[0].write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with outputs[1].open("w", encoding="utf-8") as output:
        output.write(
            "rank\tperiod_percent\tsample_percent\tperiod_sum\tsample_count\t"
            "address\toffset\tsize\tbytes\tinstruction\n"
        )
        for instruction in sampled:
            output.write(
                f"{instruction['rank']}\t{instruction['periodPercent']:.6f}\t"
                f"{instruction['samplePercent']:.6f}\t{instruction['periodSum']}\t"
                f"{instruction['sampleCount']}\t{instruction['address']}\t"
                f"{instruction['offset']}\t{instruction['size']}\t"
                f"{instruction['bytes']}\t{instruction['text'].replace(chr(9), ' ')}\n"
            )
    lines = [
        f"Function: {function['name']}",
        f"Samples: {totals['mappedRows']}/{totals['sampleRows']} mapped",
        f"Unmapped period: {unmapped_percent:.6f}%",
        "",
        "Rank  Period%  Samples  Address     Offset   Instruction",
    ]
    for instruction in sampled[:40]:
        lines.append(
            f"{instruction['rank']:>4}  {instruction['periodPercent']:>7.3f}  "
            f"{instruction['sampleCount']:>7}  {instruction['address']:>10}  "
            f"{instruction['offset']:>7}  {instruction['text']}"
        )
    outputs[2].write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report


def self_test() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        bundle = Path(temporary)
        ida = bundle / "ida"
        ida.mkdir()
        (ida / "summary.json").write_text(
            json.dumps(
                {
                    "inputSha256": "a" * 64,
                    "function": {
                        "name": "raw_symbol",
                        "start": "0x1000",
                        "end": "0x1004",
                        "instructionCount": 2,
                    },
                }
            ),
            encoding="utf-8",
        )
        (ida / "disassembly.json").write_text(
            json.dumps(
                [
                    {"address": "0x1000", "size": 2, "bytes": "9090", "text": "nop"},
                    {"address": "0x1002", "size": 2, "bytes": "c3cc", "text": "ret"},
                ]
            ),
            encoding="utf-8",
        )
        (bundle / "perf-symbol-samples.txt").write_text(
            "# binary_sha256=" + "a" * 64 + "\n"
            "# binary_build_id=abcdef01\n"
            "# raw_symbol=raw_symbol\n"
            "# dso_basename=rust-reality\n"
            "10 0x1 raw_symbol+0x0 (/tmp/rust-reality)\n"
            "30 0x3 raw_symbol+0x3 (/tmp/rust-reality)\n",
            encoding="utf-8",
        )
        report = aggregate(bundle, 0.0)
        assert report["totals"]["mappedRows"] == 2
        assert report["instructions"][0]["offset"] == "0x2"
    print("aggregate-hotspot-samples self-test: PASS")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", nargs="?")
    parser.add_argument("--max-unmapped-period-percent", type=float, default=0.0)
    parser.add_argument("--unmapped-period-explanation")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if not args.bundle:
        parser.error("bundle is required unless --self-test is used")
    if not 0.0 <= args.max_unmapped_period_percent < 1.0:
        parser.error("mapping threshold must be in [0, 1)")
    if args.unmapped_period_explanation and args.max_unmapped_period_percent == 0:
        parser.error("an unmapped-period explanation requires a non-zero sub-1% threshold")
    report = aggregate(
        Path(args.bundle).resolve(),
        args.max_unmapped_period_percent,
        args.unmapped_period_explanation,
    )
    print(
        f"mapped {report['totals']['mappedRows']}/{report['totals']['sampleRows']} "
        f"samples; unmapped period {report['totals']['unmappedPeriodPercent']:.6f}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
