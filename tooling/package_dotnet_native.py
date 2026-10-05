#!/usr/bin/env python3
"""Stages and verifies the experimental Windows x64 native artifact of the .NET package (P9-D-006).

The bundle `sas-pairing-dotnet-windows-x64-abi1` holds exactly nine files: the native ABI v1
library `sas_pairing_core.dll`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`, the artifact
`README.md`, the project licenses `LICENSE-MIT` and `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.md`,
the frozen header `sas_pairing.h`, and the frozen `abi-v1-manifest.md`. It is distributed
separately from the managed `SasPairing` NuGet-format package, which contains no native library.

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
  python3 tooling/package_dotnet_native.py stage --library <built dll> --output <new directory>
      --git-sha <40 hex digits> --rust-target x86_64-pc-windows-msvc [--cargo-metadata <json>]
  python3 tooling/package_dotnet_native.py verify --bundle <directory> --git-sha <40 hex digits>
      [--source-library <built dll>]

The PE reader, the export audit, the version readers, and the dependency-graph walk are reused
from the P8 tool (`package_dart_native.py`, imported and unchanged); the P8 bundle contract is not
affected. A checksum is integrity metadata, not a signature: the DLL is not code-signed. Exit
status 1 on any problem, with every problem listed. Python standard library only.
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import sys

TOOLING = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TOOLING)
if TOOLING not in sys.path:
    sys.path.insert(0, TOOLING)

import package_dart_native as p8  # noqa: E402  (PE checks, export audit, versions, cargo metadata)

BUNDLE_NAME = "sas-pairing-dotnet-windows-x64-abi1"
NUGET_BUNDLE_NAME = "sas-pairing-dotnet-nuget"
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
    "dotnet_package_version",
    "export_count",
    "git_commit",
    "library_file",
    "library_sha256",
    "platform",
    "rust_target",
    "schema_version",
    "security_status",
)
FORBIDDEN_SUFFIXES = dict(p8.FORBIDDEN_SUFFIXES, **{".nupkg": "a NuGet package (the managed package is a separate artifact)"})

NOTICES_TITLE = p8.NOTICES_TITLE
NOTICES_HEADER = p8.NOTICES_HEADER
SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
SUM_LINE = re.compile(r"([0-9a-f]{64})  (\S+)")

PackagingError = p8.PackagingError
check_amd64_dll = p8.check_amd64_dll
check_exports = p8.check_exports
pe_header = p8.pe_header
core_crate_version = p8.core_crate_version
header_abi_version = p8.header_abi_version
manifest_export_names = p8.manifest_export_names
run_cargo_metadata = p8.run_cargo_metadata
third_party_packages = p8.third_party_packages


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


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def repository_file(relative):
    return os.path.join(ROOT, *relative.split("/"))


# --- Repository-derived values ------------------------------------------------------------------


def csproj_property(name):
    """A property of dotnet/src/SasPairing/SasPairing.csproj (text of its one element)."""
    text = read_bytes(repository_file("dotnet/src/SasPairing/SasPairing.csproj")).decode("utf-8-sig")
    values = re.findall(rf"<{name}>([^<]*)</{name}>", text)
    if len(values) != 1:
        raise PackagingError(f"SasPairing.csproj must define {name} exactly once")
    return values[0].strip()


def dotnet_package_version():
    """VersionPrefix-VersionSuffix of the SasPairing project (P9-D-001 A: 0.1.0-dev.1)."""
    prefix, suffix = csproj_property("VersionPrefix"), csproj_property("VersionSuffix")
    return f"{prefix}-{suffix}" if suffix else prefix


def dotnet_target_framework():
    """The one TargetFramework of dotnet/Directory.Build.props (no multi-targeting)."""
    text = read_bytes(repository_file("dotnet/Directory.Build.props")).decode("utf-8-sig")
    if "<TargetFrameworks>" in text:
        raise PackagingError("Directory.Build.props multi-targets; P9 has exactly one target framework")
    values = re.findall(r"<TargetFramework>([^<]*)</TargetFramework>", text)
    if len(values) != 1:
        raise PackagingError("Directory.Build.props must define TargetFramework exactly once")
    return values[0].strip()


# --- Shared bundle helpers (also used by package_dotnet_nuget.py) ---------------------------------


def manifest_bytes(manifest):
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sums_text(directory, bundle_files):
    lines = [
        f"{sha256_file(os.path.join(directory, name))}  {name}"
        for name in bundle_files
        if name != SUMS_FILE
    ]
    return "\n".join(lines) + "\n"


def verify_sums(bundle, bundle_files):
    """(problems, {file: listed digest}) of the bundle's SHA256SUMS.txt against its files."""
    try:
        text = read_bytes(os.path.join(bundle, SUMS_FILE)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{SUMS_FILE}: unreadable: {error}"], {}
    problems = []
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
    expected_names = [name for name in bundle_files if name != SUMS_FILE]
    for name in expected_names:
        if name not in entries:
            problems.append(f"{SUMS_FILE}: no checksum for {name}")
        elif os.path.isfile(os.path.join(bundle, name)):
            actual = sha256_file(os.path.join(bundle, name))
            if actual != entries[name]:
                problems.append(f"{SUMS_FILE}: SHA-256 mismatch for {name} (listed {entries[name]}, actual {actual})")
    for name in sorted(set(entries) - set(expected_names)):
        problems.append(f"{SUMS_FILE}: unexpected entry {name}")
    return problems, entries


def verify_file_set(bundle, bundle_files, forbidden_suffixes):
    problems = []
    for name in sorted(os.listdir(bundle)):
        path = os.path.join(bundle, name)
        if os.path.isdir(path):
            problems.append(f"unexpected directory {name}/")
        elif name not in bundle_files:
            reason = next(
                (why for suffix, why in forbidden_suffixes.items() if name.lower().endswith(suffix)),
                "not part of the bundle contract",
            )
            problems.append(f"unexpected file {name} ({reason})")
    for name in bundle_files:
        if not os.path.isfile(os.path.join(bundle, name)):
            problems.append(f"missing file {name}")
    return problems


def check_manifest_values(manifest, expected, fields, manifest_file=MANIFEST_FILE):
    """Exact field set, and every expected value with its exact JSON type (bool is not int)."""
    if not isinstance(manifest, dict):
        return [f"{manifest_file} is not a JSON object"]
    problems = []
    for name in sorted(set(fields) - set(manifest)):
        problems.append(f"{manifest_file}: missing field {name}")
    for name in sorted(set(manifest) - set(fields)):
        problems.append(f"{manifest_file}: unknown field {name}")
    for name, value in expected.items():
        actual = manifest.get(name)
        if name in manifest and (actual != value or type(actual) is not type(value)):
            problems.append(f"{manifest_file}: {name} is {actual!r}, expected {value!r}")
    return problems


def read_manifest(bundle, verify_manifest):
    """(problems, manifest or None): parse, check the deterministic form, then the values."""
    path = os.path.join(bundle, MANIFEST_FILE)
    if not os.path.isfile(path):
        return [], None
    try:
        manifest = json.loads(read_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return [f"{MANIFEST_FILE}: not valid JSON: {error}"], None
    problems = verify_manifest(manifest)
    if manifest_bytes(manifest) != read_bytes(path):
        problems.append(f"{MANIFEST_FILE}: not in the deterministic form (sorted keys, indent 2, LF)")
    return problems, manifest


# --- Generated files ----------------------------------------------------------------------------


def notices_markdown(metadata, rust_target):
    rows = third_party_packages(metadata)
    lines = [
        NOTICES_TITLE,
        "",
        "Inventory of the third-party Rust packages in the locked dependency graph of the "
        f"`sas-pairing-core` crate for `{rust_target}`, generated by "
        "`tooling/package_dotnet_native.py` from `cargo metadata --locked --format-version 1 "
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
        "dotnet_package_version": dotnet_package_version(),
        "export_count": EXPORT_COUNT,
        "git_commit": git_sha,
        "library_file": LIBRARY_FILE,
        "library_sha256": library_sha256,
        "platform": PLATFORM,
        "rust_target": rust_target,
        "schema_version": SCHEMA_VERSION,
        "security_status": SECURITY_STATUS,
    }


def readme_markdown(manifest):
    sha = manifest["git_commit"]
    version = manifest["dotnet_package_version"]
    return f"""# {BUNDLE_NAME}

**Experimental, pre-alpha CI artifact. Not production-security approved, not professionally audited, and not formally verified. Do not use it to protect production systems. No production release is implied.**

This is the native library of the sas-pairing .NET package (`SasPairing` {version}) for **Windows x64 only** (`{manifest["rust_target"]}`), built and tested by the repository's CI from one exact commit. The managed package `SasPairing.{version}.nupkg` is a separate artifact (`{NUGET_BUNDLE_NAME}-{sha}`) and contains no native library.

| Item | Value |
|---|---|
| Commit | `{sha}` |
| Library | `{LIBRARY_FILE}` (SHA-256 `{manifest["library_sha256"]}`) |
| Native ABI | version {manifest["abi_version"]} (ABI v1), exactly {manifest["export_count"]} exports |
| .NET package | `SasPairing` {version} (`net10.0`) |
| Core crate | `sas-pairing-core` {manifest["core_crate_version"]} |
| Platform | Windows x64 (PE machine AMD64) |
| Code signing | **not code-signed** |

## Verify

1. `ARTIFACT-MANIFEST.json` must name the commit `{sha}` and ABI version 1.
2. Check the SHA-256 values in `SHA256SUMS.txt`, for example `sha256sum -c SHA256SUMS.txt`, or in PowerShell `Get-FileHash -Algorithm SHA256 .\\{LIBRARY_FILE}` against the `{LIBRARY_FILE}` line and `library_sha256`.
3. From a checkout of the same commit: `python tooling/package_dotnet_native.py verify --bundle <this directory> --git-sha {sha}`.

A matching checksum shows that the files are intact relative to this metadata. **The checksum is integrity metadata, not a digital signature**: it does not prove who built the file, that the build was secure, or that the file carries a code signature, and a checksum file shipped in the same download cannot detect a replaced download. Obtain the artifact only from the repository's own GitHub Actions run of this commit.

## Use

- Use the managed package `SasPairing` {version} from the **same commit** `{sha}` (artifact `{NUGET_BUNDLE_NAME}-{sha}`); do not mix this DLL with another commit's wrapper.
- Extract this bundle once and pass the **absolute path** of `{LIBRARY_FILE}` to `SasPairingRuntime.Create(nativeLibraryPath)`. The .NET loader requires an explicit absolute path and searches for nothing: no `PATH`, application, current, or package directory, and no download.
- **Load one copy only.** One native image per process; do not load multiple copies of this library (from different paths or load contexts).
- **Do not unload or reload it.** The image stays resident until the process exits (the package never calls `NativeLibrary.Free`); never replace the file while a process uses it.
- **`SAS_PAIRING_FATAL` requires an OS process restart.** There is no reset or reload recovery.
- Pairing networking is supported on Windows only. Linux, macOS, and mobile pairing are **not supported**, and no Linux, macOS, mobile, ARM64, or 32-bit artifact is distributed.

## Contents

`{LIBRARY_FILE}`, `{MANIFEST_FILE}`, `{SUMS_FILE}`, `{README_FILE}`, `LICENSE-MIT`, `LICENSE-APACHE`, `{NOTICES_FILE}` (the third-party dependency license inventory; not legal advice), `sas_pairing.h` (the frozen ABI v1 header), and `abi-v1-manifest.md` (the frozen ABI v1 manifest). The library is licensed under MIT OR Apache-2.0.

This GitHub Actions artifact expires after its retention period. It is not a GitHub Release, a tag, or a NuGet feed publication.
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
    "contains no native library",
)
FALSE_CLAIMS = ("is code-signed", "is signed", "digitally signed", "production-ready", "production ready")


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
    write_bytes(os.path.join(output, SUMS_FILE), sums_text(output, BUNDLE_FILES).encode("utf-8"))

    problems = verify(output, git_sha, source_library=library)
    if problems:
        raise PackagingError("the staged bundle fails verification: " + "; ".join(problems))
    return manifest


# --- Verify -------------------------------------------------------------------------------------


def verify_manifest(manifest, git_sha):
    try:
        expected = {
            "abi_version": ABI_VERSION,
            "architecture": ARCHITECTURE,
            "bundle_name": BUNDLE_NAME,
            "core_crate_version": core_crate_version(),
            "dotnet_package_version": dotnet_package_version(),
            "export_count": EXPORT_COUNT,
            "git_commit": git_sha,
            "library_file": LIBRARY_FILE,
            "platform": PLATFORM,
            "rust_target": RUST_TARGET,
            "schema_version": SCHEMA_VERSION,
            "security_status": SECURITY_STATUS,
        }
    except PackagingError as error:
        return [str(error)]
    problems = check_manifest_values(manifest, expected, MANIFEST_FIELDS)
    if not isinstance(manifest, dict):
        return problems
    if "code_signed" in manifest and manifest["code_signed"] is not False:
        problems.append(
            f"{MANIFEST_FILE}: code_signed is {manifest['code_signed']!r}; no signing step exists, it must be false"
        )
    digest = manifest.get("library_sha256")
    if "library_sha256" in manifest and not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
        problems.append(f"{MANIFEST_FILE}: library_sha256 is not 64 lowercase hex digits")
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
        for name in ("git_commit", "dotnet_package_version", "library_sha256"):
            if str(manifest.get(name)) not in text:
                problems.append(f"{README_FILE}: does not state {name}")
    lowered = text.lower()
    for claim in FALSE_CLAIMS:
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
    problems += verify_file_set(bundle, BUNDLE_FILES, FORBIDDEN_SUFFIXES)
    manifest_problems, manifest = read_manifest(bundle, lambda m: verify_manifest(m, git_sha))
    problems += manifest_problems

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
        sum_problems, entries = verify_sums(bundle, BUNDLE_FILES)
        problems += sum_problems
        if isinstance(manifest, dict) and entries.get(LIBRARY_FILE) != manifest.get("library_sha256"):
            problems.append(f"{SUMS_FILE}: the {LIBRARY_FILE} line does not equal library_sha256")
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
