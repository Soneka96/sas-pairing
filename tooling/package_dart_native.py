#!/usr/bin/env python3
"""Stages and verifies the experimental Windows x64 native artifact of the Dart package (P8-D-006).

The bundle `sas-pairing-dart-windows-x64-abi1` holds exactly nine files: the native ABI v1
library `sas_pairing_core.dll`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, the artifact
`README.md`, the project licenses `LICENSE-MIT` and `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`,
the frozen header `sas_pairing.h`, and the frozen `abi-v1-manifest.md`.

  stage    copies an already built DLL into a new bundle directory and generates the metadata.
           Inputs are explicit (no directory is searched for a library) and nothing is
           compiled. The DLL must be a PE32+ AMD64 DLL exporting exactly the 25 exports of the
           ABI v1 manifest; it is copied byte for byte (equal SHA-256 before and after), and the
           finished bundle must pass `verify`.
  verify   checks an existing bundle: the exact file set, the manifest fields and values, the
           SHA-256 checksums, the PE machine and the exports of the DLL, the copied repository
           files, the notices and README structure, and (with --source-library) that the
           staged DLL is byte-identical to the build output.

Usage:
  python3 tooling/package_dart_native.py stage --library <built dll> --output <new directory>
      --git-sha <40 hex digits> --rust-target x86_64-pc-windows-msvc [--cargo-metadata <json>]
  python3 tooling/package_dart_native.py verify --bundle <directory> --git-sha <40 hex digits>
      [--source-library <built dll>]

A checksum is integrity metadata, not a signature: the DLL is not code-signed. Exit status 1 on
any problem, with every problem listed. Python standard library only.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

TOOLING = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLING)
if TOOLING not in sys.path:
    sys.path.insert(0, TOOLING)

import check_abi_exports  # noqa: E402  (the export audit's own PE reader and manifest parser)

BUNDLE_NAME = "sas-pairing-dart-windows-x64-abi1"
LIBRARY_FILE = "sas_pairing_core.dll"
MANIFEST_FILE = "ARTIFACT-MANIFEST.json"
SUMS_FILE = "SHA256SUMS.txt"
README_FILE = "README.md"
NOTICES_FILE = "THIRD-PARTY-NOTICES.md"
RUST_TARGET = "x86_64-pc-windows-msvc"
PLATFORM = "windows"
ARCHITECTURE = "x86_64"
ABI_VERSION = 1
EXPORT_COUNT = 25
SCHEMA_VERSION = 1
SECURITY_STATUS = "experimental-pre-alpha"

# Bundle file name -> repository source, copied byte for byte and never modified.
COPIED_FILES = {
    "LICENSE-MIT": "LICENSE-MIT",
    "LICENSE-APACHE": "LICENSE-APACHE",
    "sas_pairing.h": "core/include/sas_pairing.h",
    "abi-v1-manifest.md": "docs/p7-native-abi/abi-v1-manifest.md",
}
BUNDLE_FILES = tuple(
    sorted([LIBRARY_FILE, MANIFEST_FILE, SUMS_FILE, README_FILE, NOTICES_FILE, *COPIED_FILES])
)
MANIFEST_FIELDS = (
    "abi_version",
    "architecture",
    "bundle_name",
    "code_signed",
    "core_crate_version",
    "dart_package_version",
    "export_count",
    "git_commit",
    "library_file",
    "library_sha256",
    "platform",
    "rust_target",
    "schema_version",
    "security_status",
)
FORBIDDEN_SUFFIXES = {
    ".pdb": "debug symbols",
    ".lib": "an import library",
    ".exp": "an export file",
    ".ilk": "an incremental-link file",
    ".so": "a Linux library (not a distributed pairing artifact)",
    ".dylib": "a macOS library",
    ".dll": "a second DLL",
    ".exe": "an executable",
    ".log": "a log file",
}

IMAGE_FILE_MACHINE_AMD64 = 0x8664
MACHINE_NAMES = {
    0x014C: "x86 (i386)",
    0x0200: "IA64",
    0x01C4: "ARMNT",
    0x8664: "AMD64 (x86_64)",
    0xA641: "ARM64EC",
    0xA64E: "ARM64X",
    0xAA64: "ARM64",
}
PE32_PLUS_MAGIC = 0x20B
IMAGE_FILE_DLL = 0x2000

NOTICES_TITLE = "# Third-party notices: sas_pairing_core.dll (Windows x64)"
NOTICES_HEADER = "| Package | Version | License (from package metadata) | Dependency kinds | Repository or source |"
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
SUM_LINE = re.compile(r"([0-9a-f]{64})  (\S+)")


class PackagingError(Exception):
    """A condition that stops staging; the message names it."""


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_bytes(path):
    with open(path, "rb") as handle:
        return handle.read()


def repository_file(relative):
    return os.path.join(ROOT, *relative.split("/"))


# --- Repository-derived values ------------------------------------------------------------------


def dart_package_version():
    text = read_bytes(repository_file("dart/pubspec.yaml")).decode("utf-8")
    match = re.search(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if not match:
        raise PackagingError("dart/pubspec.yaml has no version")
    return match.group(1)


def core_crate_version():
    text = read_bytes(repository_file("core/Cargo.toml")).decode("utf-8")
    package = re.search(r"^\[package\]\s*$(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    match = package and re.search(r'^version\s*=\s*"([^"]+)"\s*$', package.group(1), re.MULTILINE)
    if not match:
        raise PackagingError("core/Cargo.toml has no [package] version")
    return match.group(1)


def header_abi_version():
    text = read_bytes(repository_file("core/include/sas_pairing.h")).decode("utf-8")
    match = re.search(r"^#define SAS_PAIRING_ABI_VERSION (\d+)u?\s*$", text, re.MULTILINE)
    if not match:
        raise PackagingError("the header defines no SAS_PAIRING_ABI_VERSION")
    return int(match.group(1))


def manifest_export_names():
    try:
        return check_abi_exports.manifest_exports()
    except SystemExit as error:
        raise PackagingError(f"ABI v1 manifest: {error}") from None


# --- PE checks ----------------------------------------------------------------------------------


def pe_header(data):
    """(machine, characteristics, optional-header magic) of a PE image, or PackagingError."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PackagingError("not a PE image (no MZ header)")
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if pe_offset + 24 + 2 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PackagingError("malformed PE image (no PE signature)")
    machine, _sections, _stamp, _symbols, _count, optional_size, characteristics = (
        struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    )
    if optional_size < 2:
        raise PackagingError("malformed PE image (no optional header)")
    (magic,) = struct.unpack_from("<H", data, pe_offset + 24)
    return machine, characteristics, magic


def check_amd64_dll(data):
    """Raises PackagingError unless [data] is a PE32+ AMD64 DLL; returns the machine name."""
    machine, characteristics, magic = pe_header(data)
    if machine != IMAGE_FILE_MACHINE_AMD64:
        name = MACHINE_NAMES.get(machine, "unknown")
        raise PackagingError(
            f"PE machine {machine:#06x} ({name}) is not AMD64 (0x8664); only Windows x64 is distributed"
        )
    if magic != PE32_PLUS_MAGIC:
        raise PackagingError(f"optional-header magic {magic:#06x} is not PE32+ (0x020b)")
    if not characteristics & IMAGE_FILE_DLL:
        raise PackagingError("the PE image is not a DLL")
    return MACHINE_NAMES[machine]


def check_exports(data):
    """Raises PackagingError unless the DLL exports exactly the 25 manifest exports."""
    expected = manifest_export_names()
    if len(expected) != EXPORT_COUNT or len(set(expected)) != EXPORT_COUNT:
        raise PackagingError(f"the ABI v1 manifest lists {len(expected)} exports, not {EXPORT_COUNT}")
    try:
        exported = check_abi_exports.pe_exports(data)
    except (SystemExit, struct.error, ValueError, IndexError, UnicodeDecodeError) as error:
        raise PackagingError(f"unreadable PE export table: {error}") from None
    problems = [f"missing export {name}" for name in expected if name not in exported]
    problems += [f"unexpected export {name}" for name in sorted(set(exported) - set(expected))]
    if len(exported) != len(set(exported)):
        problems.append("a symbol is exported twice")
    if problems:
        raise PackagingError("export audit: " + "; ".join(problems))
    return len(exported)


# --- Generated files ----------------------------------------------------------------------------


def run_cargo_metadata(rust_target):
    command = [
        "cargo",
        "metadata",
        "--manifest-path",
        repository_file("core/Cargo.toml"),
        "--locked",
        "--format-version",
        "1",
        "--filter-platform",
        rust_target,
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        raise PackagingError(f"cargo metadata failed: {completed.stderr.strip()}")
    return json.loads(completed.stdout)


def third_party_packages(metadata):
    """Every package reachable from the root crate through non-development edges, sorted."""
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    root = metadata["resolve"]["root"]
    if root is None:
        raise PackagingError("cargo metadata has no root package")
    kinds = {}
    pending = [root]
    while pending:
        node = nodes[pending.pop()]
        for dependency in node["deps"]:
            edge = {kind["kind"] or "normal" for kind in dependency["dep_kinds"]} - {"dev"}
            if not edge:
                continue
            if dependency["pkg"] not in kinds:
                pending.append(dependency["pkg"])
            kinds.setdefault(dependency["pkg"], set()).update(edge)
    rows = []
    for package_id, package_kinds in kinds.items():
        package = packages[package_id]
        license_expression = (package.get("license") or "").strip()
        if not license_expression:
            raise PackagingError(
                f"STOP: {package['name']} {package['version']} has no license metadata; "
                "no license is guessed"
            )
        source = package.get("repository") or package.get("source") or "(no repository metadata)"
        rows.append(
            (
                package["name"],
                package["version"],
                license_expression,
                ", ".join(sorted(package_kinds)),
                source,
            )
        )
    return sorted(rows)


def notices_markdown(metadata, rust_target):
    rows = third_party_packages(metadata)
    lines = [
        NOTICES_TITLE,
        "",
        "Inventory of the third-party Rust packages in the locked dependency graph of the "
        f"`sas-pairing-core` crate for `{rust_target}`, generated by "
        "`tooling/package_dart_native.py` from `cargo metadata --locked --format-version 1 "
        f"--filter-platform {rust_target}` (`core/Cargo.lock`). Every package reachable from "
        "the crate through a normal or build dependency edge is listed (procedural macros "
        "and build-only packages included, development-only packages excluded), so the list "
        "may conservatively include packages whose code is not linked into the DLL.",
        "",
        "The license column repeats each package's own license metadata. This inventory is "
        "not legal advice and does not establish that every licensing obligation is met; the "
        "full license texts are in each package's source distribution. `sas-pairing-core` "
        "itself is licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).",
        "",
        f"Packages: {len(rows)}.",
        "",
        NOTICES_HEADER,
        "|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")
    return "\n".join(lines) + "\n"


def artifact_manifest(git_sha, rust_target, library_sha256):
    return {
        "abi_version": ABI_VERSION,
        "architecture": ARCHITECTURE,
        "bundle_name": BUNDLE_NAME,
        "code_signed": False,
        "core_crate_version": core_crate_version(),
        "dart_package_version": dart_package_version(),
        "export_count": EXPORT_COUNT,
        "git_commit": git_sha,
        "library_file": LIBRARY_FILE,
        "library_sha256": library_sha256,
        "platform": PLATFORM,
        "rust_target": rust_target,
        "schema_version": SCHEMA_VERSION,
        "security_status": SECURITY_STATUS,
    }


def manifest_bytes(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def readme_markdown(manifest):
    sha = manifest["git_commit"]
    return f"""# {BUNDLE_NAME}

**Experimental, pre-alpha CI artifact. Not production-security approved, not professionally audited, and not formally verified. Do not use it to protect production systems. No production release is implied.**

This is the native library of the sas-pairing Dart package (`sas_pairing` {manifest["dart_package_version"]}) for **Windows x64 only** (`{manifest["rust_target"]}`), built and tested by the repository's CI from one exact commit.

| Item | Value |
|---|---|
| Commit | `{sha}` |
| Library | `{LIBRARY_FILE}` (SHA-256 `{manifest["library_sha256"]}`) |
| Native ABI | version {manifest["abi_version"]} (ABI v1), exactly {manifest["export_count"]} exports |
| Dart package | `sas_pairing` {manifest["dart_package_version"]} |
| Core crate | `sas-pairing-core` {manifest["core_crate_version"]} |
| Platform | Windows x64 (PE machine AMD64) |
| Code signing | **not code-signed** |

## Verify

1. `ARTIFACT-MANIFEST.json` must name the commit `{sha}` and ABI version 1.
2. Check the SHA-256 values in `SHA256SUMS.txt`, for example `sha256sum -c SHA256SUMS.txt`, or in PowerShell `Get-FileHash -Algorithm SHA256 .\\{LIBRARY_FILE}` against the `{LIBRARY_FILE}` line and `library_sha256`.
3. From a checkout of the same commit: `python tooling/package_dart_native.py verify --bundle <this directory> --git-sha {sha}`.

A matching checksum shows that the files are intact relative to this metadata. **The checksum is integrity metadata, not a digital signature**: it does not prove who built the file, that the build was secure, or that the file carries a code signature, and a checksum file shipped in the same download cannot detect a replaced download. Obtain the artifact only from the repository's own GitHub Actions run of this commit.

## Use

- Use the Dart package source from the **same commit** `{sha}`; do not mix this DLL with another commit's wrapper.
- Extract this bundle once and pass the **absolute path** of `{LIBRARY_FILE}` to `SasPairingRuntime.create(nativeLibraryPath: ...)`. The Dart loader requires an explicit absolute path and searches for nothing.
- **Load one copy only.** Do not load multiple copies of this library in one process (from different paths or isolates).
- **Do not unload or reload it.** The image stays resident until the process exits; never replace the file while a process uses it.
- **`SAS_PAIRING_FATAL` requires an OS process restart.** There is no reset or reload recovery.
- Pairing networking is supported on Windows only. Linux, macOS, and mobile pairing are **not supported**, and no Linux, macOS, mobile, ARM64, or 32-bit artifact is distributed.

## Contents

`{LIBRARY_FILE}`, `{MANIFEST_FILE}`, `{SUMS_FILE}`, `{README_FILE}`, `LICENSE-MIT`, `LICENSE-APACHE`, `{NOTICES_FILE}` (the third-party dependency license inventory; not legal advice), `sas_pairing.h` (the frozen ABI v1 header), and `abi-v1-manifest.md` (the frozen ABI v1 manifest). The library is licensed under MIT OR Apache-2.0.

This GitHub Actions artifact expires after its retention period. It is not a GitHub Release, a tag, or a pub.dev package.
"""


README_REQUIRED = (
    "Experimental, pre-alpha CI artifact",
    "Not production-security approved",
    "No production release is implied",
    "**Windows x64 only**",
    "ABI v1",
    "**not code-signed**",
    "not a digital signature",
    "**absolute path**",
    "Load one copy only.",
    "Do not unload or reload it.",
    "requires an OS process restart",
    "are **not supported**",
    "**same commit**",
)


def sums_text(directory):
    lines = [
        f"{sha256_file(os.path.join(directory, name))}  {name}"
        for name in BUNDLE_FILES
        if name != SUMS_FILE
    ]
    return "\n".join(lines) + "\n"


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


# --- Stage --------------------------------------------------------------------------------------


def stage(library, output, git_sha, rust_target, metadata=None):
    """Stages a bundle into the new directory [output]; returns the manifest."""
    if not SHA_PATTERN.fullmatch(git_sha):
        raise PackagingError(f"--git-sha must be a full 40-hex-digit lowercase commit: {git_sha!r}")
    if rust_target != RUST_TARGET:
        raise PackagingError(f"--rust-target {rust_target!r} is not {RUST_TARGET}; only Windows x64 is distributed")
    if os.path.basename(library) != LIBRARY_FILE or not os.path.isfile(library):
        raise PackagingError(f"--library must name an existing {LIBRARY_FILE}: {library}")
    if os.path.exists(output) and (not os.path.isdir(output) or os.listdir(output)):
        raise PackagingError(f"--output must be a new or empty directory: {output}")
    if header_abi_version() != ABI_VERSION:
        raise PackagingError(f"the header's SAS_PAIRING_ABI_VERSION is not {ABI_VERSION}")
    if len(manifest_export_names()) != EXPORT_COUNT:
        raise PackagingError(f"the ABI v1 manifest does not list {EXPORT_COUNT} exports")

    source = read_bytes(library)
    source_sha256 = sha256_bytes(source)
    check_amd64_dll(source)
    check_exports(source)
    notices = notices_markdown(metadata if metadata is not None else run_cargo_metadata(rust_target), rust_target)

    os.makedirs(output, exist_ok=True)
    staged_library = os.path.join(output, LIBRARY_FILE)
    shutil.copyfile(library, staged_library)
    staged_sha256 = sha256_file(staged_library)
    if staged_sha256 != source_sha256 or sha256_file(library) != source_sha256:
        raise PackagingError(
            f"STOP: the staged DLL ({staged_sha256}) is not byte-identical to the build output ({source_sha256})"
        )
    for name, relative in COPIED_FILES.items():
        shutil.copyfile(repository_file(relative), os.path.join(output, name))
    write_bytes(os.path.join(output, NOTICES_FILE), notices.encode("utf-8"))
    manifest = artifact_manifest(git_sha, rust_target, staged_sha256)
    write_bytes(os.path.join(output, MANIFEST_FILE), manifest_bytes(manifest))
    write_bytes(os.path.join(output, README_FILE), readme_markdown(manifest).encode("utf-8"))
    write_bytes(os.path.join(output, SUMS_FILE), sums_text(output).encode("utf-8"))

    problems = verify(output, git_sha, source_library=library)
    if problems:
        raise PackagingError("the staged bundle fails verification: " + "; ".join(problems))
    return manifest


# --- Verify -------------------------------------------------------------------------------------


def verify_manifest(manifest, git_sha):
    problems = []
    if not isinstance(manifest, dict):
        return [f"{MANIFEST_FILE} is not a JSON object"]
    fields = set(manifest)
    for name in sorted(set(MANIFEST_FIELDS) - fields):
        problems.append(f"{MANIFEST_FILE}: missing field {name}")
    for name in sorted(fields - set(MANIFEST_FIELDS)):
        problems.append(f"{MANIFEST_FILE}: unknown field {name}")
    try:
        expected = {
            "abi_version": ABI_VERSION,
            "architecture": ARCHITECTURE,
            "bundle_name": BUNDLE_NAME,
            "core_crate_version": core_crate_version(),
            "dart_package_version": dart_package_version(),
            "export_count": EXPORT_COUNT,
            "git_commit": git_sha,
            "library_file": LIBRARY_FILE,
            "platform": PLATFORM,
            "rust_target": RUST_TARGET,
            "schema_version": SCHEMA_VERSION,
            "security_status": SECURITY_STATUS,
        }
    except PackagingError as error:
        return problems + [str(error)]
    for name, value in expected.items():
        actual = manifest.get(name)
        # bool is an int in Python: 1 must not be satisfied by true.
        if name in manifest and (actual != value or type(actual) is not type(value)):
            problems.append(f"{MANIFEST_FILE}: {name} is {actual!r}, expected {value!r}")
    if "code_signed" in manifest and manifest["code_signed"] is not False:
        problems.append(
            f"{MANIFEST_FILE}: code_signed is {manifest['code_signed']!r}; no signing step exists, it must be false"
        )
    digest = manifest.get("library_sha256")
    if "library_sha256" in manifest and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
        problems.append(f"{MANIFEST_FILE}: library_sha256 is not 64 lowercase hex digits")
    return problems


def verify_sums(bundle, manifest):
    problems = []
    try:
        text = read_bytes(os.path.join(bundle, SUMS_FILE)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{SUMS_FILE}: unreadable: {error}"]
    if not text.endswith("\n") or "\r" in text:
        problems.append(f"{SUMS_FILE}: not LF-terminated lines")
    entries = {}
    for line in text.splitlines():
        match = SUM_LINE.fullmatch(line)
        if not match:
            problems.append(f"{SUMS_FILE}: malformed line {line!r}")
            continue
        digest, name = match.groups()
        if name in entries:
            problems.append(f"{SUMS_FILE}: {name} listed twice")
        entries[name] = digest
    expected_names = [name for name in BUNDLE_FILES if name != SUMS_FILE]
    for name in expected_names:
        if name not in entries:
            problems.append(f"{SUMS_FILE}: no checksum for {name}")
        elif os.path.isfile(os.path.join(bundle, name)):
            actual = sha256_file(os.path.join(bundle, name))
            if actual != entries[name]:
                problems.append(f"{SUMS_FILE}: SHA-256 mismatch for {name} (listed {entries[name]}, actual {actual})")
    for name in sorted(set(entries) - set(expected_names)):
        problems.append(f"{SUMS_FILE}: unexpected entry {name}")
    if isinstance(manifest, dict) and entries.get(LIBRARY_FILE) != manifest.get("library_sha256"):
        problems.append(f"{SUMS_FILE}: the {LIBRARY_FILE} line does not equal library_sha256")
    return problems


def verify_notices(bundle):
    try:
        text = read_bytes(os.path.join(bundle, NOTICES_FILE)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{NOTICES_FILE}: unreadable: {error}"]
    problems = []
    lines = text.splitlines()
    if not lines or lines[0] != NOTICES_TITLE:
        problems.append(f"{NOTICES_FILE}: wrong title")
    if "not legal advice" not in text:
        problems.append(f"{NOTICES_FILE}: missing the not-legal-advice statement")
    if NOTICES_HEADER not in lines:
        return problems + [f"{NOTICES_FILE}: no inventory table"]
    rows = lines[lines.index(NOTICES_HEADER) + 2 :]
    if not rows:
        problems.append(f"{NOTICES_FILE}: the inventory is empty")
    for row in rows:
        cells = [cell.strip() for cell in re.split(r"(?<!\\)\|", row)[1:-1]]
        if len(cells) != 5 or not all(cells):
            problems.append(f"{NOTICES_FILE}: malformed or incomplete row {row!r}")
    count = re.search(r"^Packages: (\d+)\.$", text, re.MULTILINE)
    if not count or int(count.group(1)) != len(rows):
        problems.append(f"{NOTICES_FILE}: the package count does not match the table")
    return problems


def verify_readme(bundle, manifest):
    try:
        text = read_bytes(os.path.join(bundle, README_FILE)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{README_FILE}: unreadable: {error}"]
    problems = [f"{README_FILE}: missing statement {phrase!r}" for phrase in README_REQUIRED if phrase not in text]
    if isinstance(manifest, dict):
        for name in ("git_commit", "dart_package_version", "library_sha256"):
            if str(manifest.get(name)) not in text:
                problems.append(f"{README_FILE}: does not state {name}")
    lowered = text.lower()
    for claim in ("is code-signed", "is signed", "digitally signed", "production-ready", "production ready"):
        if claim in lowered:
            problems.append(f"{README_FILE}: false claim {claim!r}")
    return problems


def verify(bundle, git_sha, source_library=None):
    """Every problem of the bundle in [bundle] for the commit [git_sha]; empty when valid."""
    if not os.path.isdir(bundle):
        return [f"no bundle directory {bundle}"]
    problems = []
    if not SHA_PATTERN.fullmatch(git_sha or ""):
        problems.append(f"--git-sha must be a full 40-hex-digit lowercase commit: {git_sha!r}")
    present = sorted(os.listdir(bundle))
    for name in present:
        path = os.path.join(bundle, name)
        if os.path.isdir(path):
            problems.append(f"unexpected directory {name}/")
        elif name not in BUNDLE_FILES:
            reason = next(
                (why for suffix, why in FORBIDDEN_SUFFIXES.items() if name.lower().endswith(suffix)),
                "not part of the bundle contract",
            )
            problems.append(f"unexpected file {name} ({reason})")
    for name in BUNDLE_FILES:
        if not os.path.isfile(os.path.join(bundle, name)):
            problems.append(f"missing file {name}")

    manifest = None
    if os.path.isfile(os.path.join(bundle, MANIFEST_FILE)):
        try:
            manifest = json.loads(read_bytes(os.path.join(bundle, MANIFEST_FILE)).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            problems.append(f"{MANIFEST_FILE}: not valid JSON: {error}")
        else:
            problems += verify_manifest(manifest, git_sha)
            if manifest_bytes(manifest) != read_bytes(os.path.join(bundle, MANIFEST_FILE)):
                problems.append(f"{MANIFEST_FILE}: not in the deterministic form (sorted keys, indent 2, LF)")

    library = os.path.join(bundle, LIBRARY_FILE)
    if os.path.isfile(library):
        data = read_bytes(library)
        digest = sha256_bytes(data)
        if isinstance(manifest, dict) and manifest.get("library_sha256") != digest:
            problems.append(f"{LIBRARY_FILE}: SHA-256 {digest} does not equal library_sha256")
        for check in (check_amd64_dll, check_exports):
            try:
                check(data)
            except PackagingError as error:
                problems.append(f"{LIBRARY_FILE}: {error}")
        if source_library is not None:
            if not os.path.isfile(source_library):
                problems.append(f"no source library {source_library}")
            elif sha256_file(source_library) != digest:
                problems.append(
                    f"{LIBRARY_FILE}: the staged DLL is not byte-identical to the source library {source_library}"
                )

    if os.path.isfile(os.path.join(bundle, SUMS_FILE)):
        problems += verify_sums(bundle, manifest)
    for name, relative in COPIED_FILES.items():
        path = os.path.join(bundle, name)
        if os.path.isfile(path) and read_bytes(path) != read_bytes(repository_file(relative)):
            problems.append(f"{name}: differs from the repository's {relative}")
    if os.path.isfile(os.path.join(bundle, NOTICES_FILE)):
        problems += verify_notices(bundle)
    if os.path.isfile(os.path.join(bundle, README_FILE)):
        problems += verify_readme(bundle, manifest)
    return problems


# --- Command line -------------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    stage_parser = commands.add_parser("stage", help="stage a bundle from a built DLL")
    stage_parser.add_argument("--library", required=True)
    stage_parser.add_argument("--output", required=True)
    stage_parser.add_argument("--git-sha", required=True)
    stage_parser.add_argument("--rust-target", required=True)
    stage_parser.add_argument("--cargo-metadata", help="a saved `cargo metadata` JSON (default: run cargo)")
    verify_parser = commands.add_parser("verify", help="verify a staged bundle")
    verify_parser.add_argument("--bundle", required=True)
    verify_parser.add_argument("--git-sha", required=True)
    verify_parser.add_argument("--source-library", help="the build DLL the staged copy must equal")
    arguments = parser.parse_args(argv)

    if arguments.command == "stage":
        try:
            metadata = None
            if arguments.cargo_metadata:
                metadata = json.loads(read_bytes(arguments.cargo_metadata).decode("utf-8"))
            manifest = stage(
                os.path.abspath(arguments.library),
                os.path.abspath(arguments.output),
                arguments.git_sha,
                arguments.rust_target,
                metadata,
            )
        except PackagingError as error:
            print(f"::error::{error}")
            print("staging FAILED")
            return 1
        print(f"staged {BUNDLE_NAME} for {manifest['git_commit']} into {arguments.output}")
        for name in MANIFEST_FIELDS:
            print(f"  {name}: {json.dumps(manifest[name])}")
        return 0

    problems = verify(
        os.path.abspath(arguments.bundle),
        arguments.git_sha,
        os.path.abspath(arguments.source_library) if arguments.source_library else None,
    )
    for problem in problems:
        print(f"::error::{arguments.bundle}: {problem}")
    print(f"{arguments.bundle}: {len(BUNDLE_FILES)}-file bundle contract: {'FAILED' if problems else 'OK'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
