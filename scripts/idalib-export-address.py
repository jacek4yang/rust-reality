#!/usr/bin/env python3
"""Export one exact machine-code function from an isolated IDALib database."""

# IDALib requires this to be the first IDA import.
import idapro

import hashlib
import json
import sys
import traceback
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_name
import ida_ua


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def export_disassembly(start_ea: int, end_ea: int) -> list[dict]:
    instructions = []
    address = start_ea
    while address < end_ea:
        instruction = ida_ua.insn_t()
        size = ida_ua.decode_insn(instruction, address)
        if size <= 0:
            address += 1
            continue
        raw = ida_bytes.get_bytes(address, size) or b""
        text = ida_lines.generate_disasm_line(
            address, ida_lines.GENDSM_REMOVE_TAGS
        )
        instructions.append(
            {
                "address": f"0x{address:x}",
                "size": size,
                "bytes": raw.hex(),
                "text": text or "",
            }
        )
        address += size
    return instructions


def export_pseudocode(start_ea: int) -> str:
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("Hex-Rays Decompiler is unavailable")
    cfunc = ida_hexrays.decompile(start_ea)
    if cfunc is None:
        raise RuntimeError(f"Hex-Rays failed to decompile 0x{start_ea:x}")
    return "\n".join(
        ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()
    )


def main() -> int:
    if len(sys.argv) != 4:
        print(
            f"usage: {sys.argv[0]} INPUT_FILE ADDRESS OUTPUT_DIRECTORY",
            file=sys.stderr,
        )
        return 2

    input_path = Path(sys.argv[1]).resolve()
    requested_ea = int(sys.argv[2], 0)
    output_directory = Path(sys.argv[3]).resolve()
    if not input_path.is_file():
        raise FileNotFoundError(input_path)
    if output_directory.exists():
        raise FileExistsError(
            f"refusing to reuse IDA output directory: {output_directory}"
        )
    output_directory.mkdir(parents=True)

    result = idapro.open_database(str(input_path), True)
    if result != 0:
        raise RuntimeError(f"idapro.open_database failed with code {result}")

    try:
        if not ida_auto.auto_wait():
            raise RuntimeError("IDA auto-analysis was cancelled")
        function = ida_funcs.get_func(requested_ea)
        if function is None:
            raise RuntimeError(f"no IDA function contains 0x{requested_ea:x}")

        start_ea = function.start_ea
        end_ea = function.end_ea
        name = ida_name.get_ea_name(start_ea)
        instructions = export_disassembly(start_ea, end_ea)
        pseudocode = export_pseudocode(start_ea)

        assembly_path = output_directory / "disassembly.json"
        pseudocode_path = output_directory / "pseudocode.c"
        summary_path = output_directory / "summary.json"
        assembly_path.write_text(
            json.dumps(instructions, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        pseudocode_path.write_text(pseudocode + "\n", encoding="utf-8")
        summary = {
            "schemaVersion": 1,
            "inputFile": str(input_path),
            "inputSha256": sha256_file(input_path),
            "requestedAddress": f"0x{requested_ea:x}",
            "function": {
                "name": name,
                "start": f"0x{start_ea:x}",
                "end": f"0x{end_ea:x}",
                "size": end_ea - start_ea,
                "instructionCount": len(instructions),
            },
        }
        summary_path.write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8"
        )
        print(
            f"resolved {name} 0x{start_ea:x}-0x{end_ea:x}; "
            f"exported {len(instructions)} instructions",
            flush=True,
        )
        return 0
    finally:
        idapro.close_database()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        traceback.print_exc()
        raise SystemExit(1)
