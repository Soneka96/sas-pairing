#!/usr/bin/env python3
"""Audits the symbols a built sas-pairing native library exports (ABI v1 freeze, P7-D-013).

Reads the export table of a Windows DLL (PE/COFF) or the dynamic symbol table of an ELF shared
object directly, without external tools, and compares it with the 25 exports listed in
docs/p7-native-abi/abi-v1-manifest.md:

  --expect manifest   the library exports exactly the manifest's exports and nothing else
                      (no test hook, seam, Rust-mangled, or other symbol);
  --expect none       the library exports no `sas_pairing_` symbol (a build without the
                      `native-abi` feature).

Usage: python3 tooling/check_abi_exports.py --library <path> --expect manifest|none
Exit status 1 on any difference, with the difference listed.
"""

import argparse
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = os.path.join(ROOT, "docs", "p7-native-abi", "abi-v1-manifest.md")
EXPORT_ROW = re.compile(r"^\|\s*(\d+)\s*\|\s*`(sas_pairing_\w+)`\s*\|")


def manifest_exports():
    with open(MANIFEST, encoding="utf-8") as handle:
        rows = [EXPORT_ROW.match(line) for line in handle]
    exports = [(int(row.group(1)), row.group(2)) for row in rows if row]
    numbers = [number for number, _ in exports]
    if numbers != list(range(1, len(numbers) + 1)):
        sys.exit(f"manifest export numbering is not 1..n: {numbers}")
    return [name for _, name in exports]


def c_string(data, offset):
    end = data.index(b"\0", offset)
    return data[offset:end].decode("ascii")


def pe_exports(data):
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        sys.exit("not a PE image")
    coff = pe_offset + 4
    sections, optional_size = struct.unpack_from("<H12xH", data, coff + 2)
    optional = coff + 20
    (magic,) = struct.unpack_from("<H", data, optional)
    directories = optional + {0x10B: 96, 0x20B: 112}[magic]
    export_rva, export_size = struct.unpack_from("<II", data, directories)
    if export_rva == 0 or export_size == 0:
        return []
    table = []
    for index in range(sections):
        header = optional + optional_size + 40 * index
        size, address, _raw_size, raw = struct.unpack_from("<IIII", data, header + 8)
        table.append((address, size, raw))

    def file_offset(rva):
        for address, size, raw in table:
            if address <= rva < address + max(size, 1):
                return raw + rva - address
        sys.exit(f"RVA {rva:#x} is in no section")

    directory = file_offset(export_rva)
    names, names_rva = struct.unpack_from("<I4xI", data, directory + 24)
    if names == 0:
        return []
    names_at = file_offset(names_rva)
    return [
        c_string(data, file_offset(struct.unpack_from("<I", data, names_at + 4 * index)[0]))
        for index in range(names)
    ]


def elf_exports(data):
    if data[4] != 2 or data[5] != 1:
        sys.exit("only 64-bit little-endian ELF is supported")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    sections = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + shentsize * index)
        for index in range(shnum)
    ]
    exported = []
    for _name, kind, _flags, _addr, offset, size, link, _info, _align, entsize in sections:
        if kind != 11:  # SHT_DYNSYM
            continue
        strings = sections[link][4]
        for start in range(offset + entsize, offset + size, entsize):
            name, info, other, shndx = struct.unpack_from("<IBBH", data, start)
            binding, symbol_type, visibility = info >> 4, info & 0xF, other & 0x3
            if shndx == 0 or binding not in (1, 2) or visibility != 0:
                continue  # undefined, local, or hidden
            if symbol_type in (1, 2):  # OBJECT, FUNC
                exported.append(c_string(data, strings + name))
    return exported


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--library", required=True)
    parser.add_argument("--expect", choices=("manifest", "none"), required=True)
    arguments = parser.parse_args()
    with open(arguments.library, "rb") as handle:
        data = handle.read()
    if data[:2] == b"MZ":
        exported = pe_exports(data)
    elif data[:4] == b"\x7fELF":
        exported = elf_exports(data)
    else:
        sys.exit("unknown library format")
    exported_set = set(exported)
    abi = sorted(name for name in exported_set if name.startswith("sas_pairing_"))
    if arguments.expect == "none":
        problems = [f"unexpected ABI export {name}" for name in abi]
        summary = f"{len(abi)} sas_pairing_ exports (expected none)"
    else:
        expected = manifest_exports()
        if len(expected) != 25 or len(set(expected)) != 25:
            sys.exit(f"the manifest lists {len(expected)} exports, not 25 distinct")
        problems = [f"missing export {name}" for name in expected if name not in exported_set]
        problems += [
            f"unexpected export {name}"
            for name in sorted(exported_set - set(expected))
        ]
        if len(exported) != len(exported_set):
            problems.append("a symbol is exported twice")
        summary = (
            f"{len(exported_set)} exports, {len(abi)} sas_pairing_ "
            f"(expected exactly the {len(expected)} of the manifest)"
        )
    for problem in problems:
        print(f"::error::{arguments.library}: {problem}")
    print(f"{arguments.library}: {summary}: {'FAILED' if problems else 'OK'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
