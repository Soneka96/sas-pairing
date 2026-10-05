#!/usr/bin/env python3
"""Stages and verifies the experimental managed .NET package artifact (P9-D-006).

The bundle `sas-pairing-dotnet-nuget` holds exactly four files: the NuGet-format package
`SasPairing.<version>.nupkg` built by `dotnet pack`, `ARTIFACT-MANIFEST.json`, `SHA256SUMS.txt`,
and the artifact `README.md`. The package is never published to nuget.org or any other feed, and
it contains NO native library: the Windows x64 native bundle is a separate artifact
(`package_dotnet_native.py`), loaded from an explicit absolute path.

  stage    copies an already packed .nupkg byte for byte into a new bundle directory and
           generates the metadata; it builds and packs nothing. The package must pass every
           package check below, and the finished bundle must pass `verify`.
  verify   checks an existing bundle: the exact file set, the manifest fields and values, the
           SHA-256 checksums, the README, and the package itself, read as a ZIP with its .nuspec
           XML: the exact entry set (one managed `lib/<tfm>/SasPairing.dll`, its XML
           documentation, the package README equal to `dotnet/README.md`, and the NuGet
           metadata parts; no native binary, no `runtimes/`, `build/`, `tools/`, or content
           asset, no test assembly), the id, version, target framework, license expression,
           README, project and repository URL, the exact repository commit, and no package
           dependency. With --assembly (repeatable) the packed SasPairing.dll must be
           byte-identical to each given built or tested assembly.

Usage:
  python3 tooling/package_dotnet_nuget.py stage --nupkg <packed .nupkg> --output <new directory>
      --git-sha <40 hex digits> [--assembly <built SasPairing.dll>]...
  python3 tooling/package_dotnet_nuget.py verify --bundle <directory> --git-sha <40 hex digits>
      [--assembly <built SasPairing.dll>]...

The package id, version, target framework, license, and repository URL are read from
`dotnet/src/SasPairing/SasPairing.csproj` and `dotnet/Directory.Build.props`. A checksum is
integrity metadata, not a signature, publisher authenticity, or audit evidence. Exit status 1 on
any problem, with every problem listed. Python standard library only.
"""

import argparse
import io
import json
import os
import re
import shutil
import struct
import sys
import xml.etree.ElementTree as ElementTree
import zipfile

TOOLING = os.path.dirname(os.path.abspath(__file__))
if TOOLING not in sys.path:
    sys.path.insert(0, TOOLING)

import package_dotnet_native as native  # noqa: E402  (shared bundle helpers and repository values)

BUNDLE_NAME = "sas-pairing-dotnet-nuget"
NATIVE_BUNDLE_NAME = native.BUNDLE_NAME
MANIFEST_FILE = native.MANIFEST_FILE
SUMS_FILE = native.SUMS_FILE
README_FILE = native.README_FILE
SCHEMA_VERSION = 1
SECURITY_STATUS = "experimental-pre-alpha"
PACKAGE_README = "dotnet/README.md"
SHA_PATTERN = native.SHA_PATTERN
PackagingError = native.PackagingError

MANIFEST_FIELDS = (
    "assembly_sha256",
    "bundle_name",
    "git_commit",
    "native_bundle_name",
    "native_library_bundled",
    "nupkg_file",
    "nupkg_sha256",
    "package_id",
    "package_version",
    "published_to_nuget",
    "schema_version",
    "security_status",
    "target_framework",
)
FORBIDDEN_SUFFIXES = {
    ".snupkg": "a symbols package (not part of P9 distribution)",
    ".nupkg": "a second NuGet package",
    ".dll": "a loose assembly or native library",
    ".so": "a Linux library",
    ".dylib": "a macOS library",
    ".exe": "an executable",
    ".pdb": "debug symbols",
    ".log": "a log file",
}
# The only metadata a SasPairing .nuspec may carry (anything else, such as frameworkReferences,
# contentFiles, or packageTypes, is unreviewed and refused).
NUSPEC_ELEMENTS = {
    "id",
    "version",
    "authors",
    "license",
    "licenseUrl",
    "readme",
    "projectUrl",
    "description",
    "copyright",
    "repository",
    "dependencies",
    "requireLicenseAcceptance",
}
PSMDCP = re.compile(r"package/services/metadata/core-properties/[0-9A-Za-z]+\.psmdcp")
# Entries that must never be in the package: native or platform assets, build hooks, tools,
# content, analyzers, and anything named like a test or test framework.
FORBIDDEN_ENTRY = re.compile(
    r"(?i)^(?:runtimes|build|buildTransitive|buildMultiTargeting|tools|content|contentFiles|analyzers|native|ref)/"
    r"|\.(?:so|dylib|exe|pdb|a|lib|targets|props|ps1|sh|cmd|bat)$"
)
TEST_ENTRY = re.compile(r"(?i)test|xunit|nunit|mstest|testhost|moq\b|coverlet")
FALSE_CLAIMS = ("is code-signed", "is signed", "digitally signed", "production-ready", "production ready",
                "published to nuget.org", "available on nuget.org")


def package_id():
    return native.csproj_property("PackageId")


def license_expression():
    return native.csproj_property("PackageLicenseExpression")


def repository_url():
    return native.csproj_property("RepositoryUrl")


def package_version():
    return native.dotnet_package_version()


def target_framework():
    return native.dotnet_target_framework()


def nupkg_file_name():
    return f"{package_id()}.{package_version()}.nupkg"


def assembly_entry():
    return f"lib/{target_framework()}/{package_id()}.dll"


def documentation_entry():
    return f"lib/{target_framework()}/{package_id()}.xml"


def bundle_files():
    return tuple(sorted([nupkg_file_name(), MANIFEST_FILE, SUMS_FILE, README_FILE]))


# --- PE ------------------------------------------------------------------------------------------


def is_managed_assembly(data):
    """True for a PE image with a CLI (COR20) header: a managed assembly, never a native library."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if pe_offset + 24 + 2 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return False
    optional = pe_offset + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    directories = {0x10B: optional + 96, 0x20B: optional + 112}.get(magic)
    if directories is None:
        return False
    (count,) = struct.unpack_from("<I", data, directories - 4)
    clr = directories + 14 * 8
    if count <= 14 or clr + 8 > len(data):
        return False
    rva, size = struct.unpack_from("<II", data, clr)
    return rva != 0 and size != 0


# --- The package --------------------------------------------------------------------------------


def local(tag):
    return tag.rsplit("}", 1)[-1]


def read_nuspec(text):
    """(problems, metadata element or None) of the .nuspec XML text."""
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as error:
        return [f"nuspec: not valid XML: {error}"], None
    if local(root.tag) != "package":
        return ["nuspec: the root element is not <package>"], None
    metadata = [child for child in root if local(child.tag) == "metadata"]
    if len(metadata) != 1:
        return ["nuspec: exactly one <metadata> element is required"], None
    others = [local(child.tag) for child in root if local(child.tag) != "metadata"]
    problems = [f"nuspec: unexpected <{name}> element (explicit file list)" for name in others]
    return problems, metadata[0]


def check_nuspec(text, git_sha):
    problems, metadata = read_nuspec(text)
    if metadata is None:
        return problems
    elements = {}
    for child in metadata:
        name = local(child.tag)
        if name in elements:
            problems.append(f"nuspec: <{name}> appears twice")
        elements[name] = child
    for name in sorted(set(elements) - NUSPEC_ELEMENTS):
        problems.append(f"nuspec: unexpected <{name}> metadata")

    def text_of(name):
        element = elements.get(name)
        return (element.text or "").strip() if element is not None else None

    try:
        expected = {
            "id": package_id(),
            "version": package_version(),
            "readme": "README.md",
            "projectUrl": repository_url(),
        }
        tfm = target_framework()
        expression = license_expression()
        url = repository_url()
    except PackagingError as error:
        return problems + [str(error)]
    for name, value in expected.items():
        if text_of(name) != value:
            problems.append(f"nuspec: <{name}> is {text_of(name)!r}, expected {value!r}")
    if not text_of("authors"):
        problems.append("nuspec: no <authors>")
    description = text_of("description") or ""
    for phrase in ("pre-alpha", "native library is not included"):
        if phrase not in description:
            problems.append(f"nuspec: the description does not state {phrase!r}")
    license_element = elements.get("license")
    if license_element is None or license_element.get("type") != "expression" or text_of("license") != expression:
        problems.append(f"nuspec: <license type=\"expression\"> is not {expression!r}")
    if text_of("requireLicenseAcceptance") not in (None, "false"):
        problems.append("nuspec: requireLicenseAcceptance must be false")
    repository = elements.get("repository")
    if repository is None:
        problems.append("nuspec: no <repository>")
    else:
        if repository.get("type") != "git":
            problems.append(f"nuspec: repository type is {repository.get('type')!r}, expected 'git'")
        if repository.get("url") != url:
            problems.append(f"nuspec: repository url is {repository.get('url')!r}, expected {url!r}")
        if repository.get("commit") != git_sha:
            problems.append(f"nuspec: repository commit is {repository.get('commit')!r}, expected {git_sha!r}")
    dependencies = elements.get("dependencies")
    groups = [] if dependencies is None else list(dependencies)
    if len(groups) != 1 or local(groups[0].tag) != "group":
        problems.append("nuspec: <dependencies> must hold exactly one <group>")
    else:
        if groups[0].get("targetFramework") != tfm:
            problems.append(
                f"nuspec: the dependency group targets {groups[0].get('targetFramework')!r}, expected {tfm!r}"
            )
        for dependency in groups[0]:
            problems.append(f"nuspec: package dependency {dependency.get('id')!r} (the library has none)")
    return problems


def check_nupkg(data, git_sha, assemblies=()):
    """Every problem of the NuGet package bytes [data] for the commit [git_sha]."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as error:
        return [f"nupkg: not a ZIP archive: {error}"]
    problems = []
    names = [info.filename for info in archive.infolist()]
    if len(names) != len(set(names)):
        problems.append("nupkg: an entry appears twice")
    try:
        required = {
            "[Content_Types].xml": "the content-types part",
            "_rels/.rels": "the relationships part",
            f"{package_id()}.nuspec": "the nuspec",
            "README.md": "the package README",
            assembly_entry(): "the managed assembly",
            documentation_entry(): "the XML documentation",
        }
    except PackagingError as error:
        return [str(error)]
    for name in names:
        if name.startswith("/") or "\\" in name or ".." in name.split("/"):
            problems.append(f"nupkg: unsafe entry name {name!r}")
        if name in required or PSMDCP.fullmatch(name):
            continue
        if FORBIDDEN_ENTRY.search(name):
            problems.append(f"nupkg: forbidden entry {name} (a native, platform, build, tool, or content asset)")
        elif TEST_ENTRY.search(name):
            problems.append(f"nupkg: forbidden entry {name} (a test assembly or test framework)")
        elif name.lower().endswith(".dll"):
            problems.append(f"nupkg: unexpected assembly or native library {name}")
        else:
            problems.append(f"nupkg: unexpected entry {name}")
    for name, what in required.items():
        if name not in names:
            problems.append(f"nupkg: missing {what} ({name})")
    if sum(1 for name in names if PSMDCP.fullmatch(name)) != 1:
        problems.append("nupkg: exactly one core-properties part is required")

    if f"{package_id()}.nuspec" in names:
        try:
            nuspec = archive.read(f"{package_id()}.nuspec").decode("utf-8-sig")
        except UnicodeDecodeError as error:
            problems.append(f"nuspec: not UTF-8: {error}")
        else:
            problems += check_nuspec(nuspec, git_sha)
    if "README.md" in names:
        readme = native.read_bytes(native.repository_file(PACKAGE_README))
        if archive.read("README.md") != readme:
            problems.append(f"nupkg: README.md differs from {PACKAGE_README}")
    if assembly_entry() in names:
        assembly = archive.read(assembly_entry())
        if not is_managed_assembly(assembly):
            problems.append(f"nupkg: {assembly_entry()} is not a managed assembly (no CLI header)")
        for path in assemblies:
            if not os.path.isfile(path):
                problems.append(f"no built assembly {path}")
            elif native.read_bytes(path) != assembly:
                problems.append(
                    f"nupkg: {assembly_entry()} is not byte-identical to the built and tested assembly {path}"
                )
    if documentation_entry() in names:
        try:
            documentation = ElementTree.fromstring(archive.read(documentation_entry()))
            name = documentation.findtext("assembly/name")
        except ElementTree.ParseError:
            name = None
        if name != package_id():
            problems.append(f"nupkg: {documentation_entry()} is not the XML documentation of {package_id()}")
    return problems


def assembly_sha256(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return native.sha256_bytes(archive.read(assembly_entry()))


# --- Generated files ----------------------------------------------------------------------------


def artifact_manifest(git_sha, nupkg_sha256, packed_assembly_sha256):
    return {
        "assembly_sha256": packed_assembly_sha256,
        "bundle_name": BUNDLE_NAME,
        "git_commit": git_sha,
        "native_bundle_name": NATIVE_BUNDLE_NAME,
        "native_library_bundled": False,
        "nupkg_file": nupkg_file_name(),
        "nupkg_sha256": nupkg_sha256,
        "package_id": package_id(),
        "package_version": package_version(),
        "published_to_nuget": False,
        "schema_version": SCHEMA_VERSION,
        "security_status": SECURITY_STATUS,
        "target_framework": target_framework(),
    }


def readme_markdown(manifest):
    sha = manifest["git_commit"]
    version = manifest["package_version"]
    nupkg = manifest["nupkg_file"]
    return f"""# {BUNDLE_NAME}

**Experimental, pre-alpha CI artifact. Not production-security approved, not professionally audited, and not formally verified. Do not use it to protect production systems. No production release is implied.**

This is the managed .NET package `{manifest["package_id"]}` {version} (`{manifest["target_framework"]}`) as an experimental NuGet-format `.nupkg`, built and tested by the repository's CI from one exact commit. It is **not published to nuget.org** or any other package feed.

| Item | Value |
|---|---|
| Commit | `{sha}` |
| Package | `{nupkg}` (SHA-256 `{manifest["nupkg_sha256"]}`) |
| Package ID / version | `{manifest["package_id"]}` {version} |
| Target framework | `{manifest["target_framework"]}` |
| Managed assembly | `lib/{manifest["target_framework"]}/{manifest["package_id"]}.dll` (SHA-256 `{manifest["assembly_sha256"]}`) |
| Native library | **not included**: it is the separate artifact `{NATIVE_BUNDLE_NAME}-{sha}` |

## Verify

1. `ARTIFACT-MANIFEST.json` must name the commit `{sha}`; the package's own metadata (`{manifest["package_id"]}.nuspec`) names the same repository commit.
2. Check the SHA-256 values in `SHA256SUMS.txt`, for example `sha256sum -c SHA256SUMS.txt`, or in PowerShell `Get-FileHash -Algorithm SHA256 .\\{nupkg}` against `nupkg_sha256`.
3. From a checkout of the same commit: `python tooling/package_dotnet_nuget.py verify --bundle <this directory> --git-sha {sha}`.

A matching checksum shows that the files are intact relative to this metadata. **The checksum is integrity metadata, not a digital signature**: it does not prove who built the package, that the build was secure, or that it was audited, and the package is not signed. Obtain the artifact only from the repository's own GitHub Actions run of this commit.

## Use

- The package **contains no native library**. Also obtain the native Windows x64 bundle `{NATIVE_BUNDLE_NAME}-{sha}` from the **same commit** and verify it; do not mix this package with another commit's native library.
- Add this directory as a **local** package source (for example a `nuget.config` entry or `dotnet add package {manifest["package_id"]} --version {version} --source <this directory>`) and reference `{manifest["package_id"]}` version {version}.
- Extract the native bundle once and pass the **absolute path** of its `sas_pairing_core.dll` to `SasPairingRuntime.Create(nativeLibraryPath)`. The package searches for nothing: no `PATH`, application, current, or package directory, no `runtimes/` asset, and no download.
- One native image per process, resident until the process exits; `SAS_PAIRING_FATAL` requires an OS process restart.
- Windows x64 is the only pairing distribution target. The package can be referenced on other platforms, but Linux, macOS, and mobile pairing are **not supported**.

## Contents

`{nupkg}`, `{MANIFEST_FILE}`, `{SUMS_FILE}`, and `{README_FILE}`. The package is licensed under MIT OR Apache-2.0.

This GitHub Actions artifact expires after its retention period (finite retention). It is not a GitHub Release, a tag, or a NuGet feed publication.
"""


README_REQUIRED = (
    "Experimental, pre-alpha CI artifact",
    "Not production-security approved",
    "No production release is implied",
    "**not published to nuget.org**",
    "**contains no native library**",
    "**same commit**",
    "**absolute path**",
    "not a digital signature",
    "Windows x64 is the only pairing distribution target",
    "finite retention",
)


# --- Stage --------------------------------------------------------------------------------------


def stage(nupkg, output, git_sha, assemblies=()):
    """Stages a bundle into the new directory [output]; returns the manifest."""
    if not SHA_PATTERN.fullmatch(git_sha):
        raise PackagingError(f"--git-sha must be a full 40-hex-digit lowercase commit: {git_sha!r}")
    if os.path.basename(nupkg) != nupkg_file_name() or not os.path.isfile(nupkg):
        raise PackagingError(f"--nupkg must name an existing {nupkg_file_name()}: {nupkg}")
    if os.path.exists(output) and (not os.path.isdir(output) or os.listdir(output)):
        raise PackagingError(f"--output must be a new or empty directory: {output}")
    data = native.read_bytes(nupkg)
    problems = check_nupkg(data, git_sha, assemblies)
    if problems:
        raise PackagingError("the package fails verification: " + "; ".join(problems))

    os.makedirs(output, exist_ok=True)
    staged = os.path.join(output, nupkg_file_name())
    shutil.copyfile(nupkg, staged)
    if native.read_bytes(staged) != data:
        raise PackagingError("STOP: the staged package is not byte-identical to the packed package")
    manifest = artifact_manifest(git_sha, native.sha256_bytes(data), assembly_sha256(data))
    native.write_bytes(os.path.join(output, MANIFEST_FILE), native.manifest_bytes(manifest))
    native.write_bytes(os.path.join(output, README_FILE), readme_markdown(manifest).encode("utf-8"))
    native.write_bytes(os.path.join(output, SUMS_FILE), native.sums_text(output, bundle_files()).encode("utf-8"))

    problems = verify(output, git_sha, assemblies)
    if problems:
        raise PackagingError("the staged bundle fails verification: " + "; ".join(problems))
    return manifest


# --- Verify -------------------------------------------------------------------------------------


def verify_manifest(manifest, git_sha):
    try:
        expected = {
            "bundle_name": BUNDLE_NAME,
            "git_commit": git_sha,
            "native_bundle_name": NATIVE_BUNDLE_NAME,
            "native_library_bundled": False,
            "nupkg_file": nupkg_file_name(),
            "package_id": package_id(),
            "package_version": package_version(),
            "published_to_nuget": False,
            "schema_version": SCHEMA_VERSION,
            "security_status": SECURITY_STATUS,
            "target_framework": target_framework(),
        }
    except PackagingError as error:
        return [str(error)]
    problems = native.check_manifest_values(manifest, expected, MANIFEST_FIELDS)
    if isinstance(manifest, dict):
        for name in ("nupkg_sha256", "assembly_sha256"):
            value = manifest.get(name)
            if name in manifest and not (isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)):
                problems.append(f"{MANIFEST_FILE}: {name} is not 64 lowercase hex digits")
    return problems


def verify_readme(bundle, manifest):
    try:
        text = native.read_bytes(os.path.join(bundle, README_FILE)).decode("utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return [f"{README_FILE}: unreadable: {error}"]
    problems = [f"{README_FILE}: missing statement {phrase!r}" for phrase in README_REQUIRED if phrase not in text]
    if isinstance(manifest, dict):
        for name in ("git_commit", "package_version", "nupkg_sha256", "package_id"):
            if str(manifest.get(name)) not in text:
                problems.append(f"{README_FILE}: does not state {name}")
    lowered = text.lower()
    for claim in FALSE_CLAIMS:
        for match in re.finditer(re.escape(claim), lowered):
            before = lowered[max(0, match.start() - 12) : match.start()]
            if not re.search(r"\bnot\s*\**\s*$", before):
                problems.append(f"{README_FILE}: false claim {claim!r}")
    return problems


def verify(bundle, git_sha, assemblies=()):
    """Every problem of the bundle in [bundle] for the commit [git_sha]; empty when valid."""
    if not os.path.isdir(bundle):
        return [f"no bundle directory {bundle}"]
    problems = []
    if not SHA_PATTERN.fullmatch(git_sha or ""):
        problems.append(f"--git-sha must be a full 40-hex-digit lowercase commit: {git_sha!r}")
    try:
        files = bundle_files()
        nupkg_name = nupkg_file_name()
    except PackagingError as error:
        return problems + [str(error)]
    problems += native.verify_file_set(bundle, files, FORBIDDEN_SUFFIXES)
    manifest_problems, manifest = native.read_manifest(bundle, lambda m: verify_manifest(m, git_sha))
    problems += manifest_problems

    nupkg = os.path.join(bundle, nupkg_name)
    if os.path.isfile(nupkg):
        data = native.read_bytes(nupkg)
        digest = native.sha256_bytes(data)
        if isinstance(manifest, dict) and manifest.get("nupkg_sha256") != digest:
            problems.append(f"{nupkg_name}: SHA-256 {digest} does not equal nupkg_sha256")
        package_problems = check_nupkg(data, git_sha, assemblies)
        problems += package_problems
        if isinstance(manifest, dict) and not package_problems and manifest.get("assembly_sha256") != assembly_sha256(data):
            problems.append(f"{MANIFEST_FILE}: assembly_sha256 does not equal the packed {assembly_entry()}")
    if os.path.isfile(os.path.join(bundle, SUMS_FILE)):
        sum_problems, entries = native.verify_sums(bundle, files)
        problems += sum_problems
        if isinstance(manifest, dict) and entries.get(nupkg_name) != manifest.get("nupkg_sha256"):
            problems.append(f"{SUMS_FILE}: the {nupkg_name} line does not equal nupkg_sha256")
    if os.path.isfile(os.path.join(bundle, README_FILE)):
        problems += verify_readme(bundle, manifest)
    return problems


# --- Command line -------------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    stage_parser = commands.add_parser("stage", help="stage a bundle from a packed .nupkg")
    stage_parser.add_argument("--nupkg", required=True)
    stage_parser.add_argument("--output", required=True)
    stage_parser.add_argument("--git-sha", required=True)
    stage_parser.add_argument("--assembly", action="append", default=[], help="a built SasPairing.dll the packed one must equal")
    verify_parser = commands.add_parser("verify", help="verify a staged bundle")
    verify_parser.add_argument("--bundle", required=True)
    verify_parser.add_argument("--git-sha", required=True)
    verify_parser.add_argument("--assembly", action="append", default=[], help="a built SasPairing.dll the packed one must equal")
    arguments = parser.parse_args(argv)
    assemblies = [os.path.abspath(path) for path in arguments.assembly]

    if arguments.command == "stage":
        try:
            manifest = stage(os.path.abspath(arguments.nupkg), os.path.abspath(arguments.output), arguments.git_sha, assemblies)
        except PackagingError as error:
            print(f"::error::{error}")
            print("staging FAILED")
            return 1
        print(f"staged {BUNDLE_NAME} for {manifest['git_commit']} into {arguments.output}")
        for name in MANIFEST_FIELDS:
            print(f"  {name}: {json.dumps(manifest[name])}")
        return 0

    problems = verify(os.path.abspath(arguments.bundle), arguments.git_sha, assemblies)
    for problem in problems:
        print(f"::error::{arguments.bundle}: {problem}")
    print(f"{arguments.bundle}: managed package bundle contract: {'FAILED' if problems else 'OK'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
