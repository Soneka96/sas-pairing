"""Tests of tooling/package_dotnet_nuget.py, the P9-D-006 managed NuGet bundle stager and verifier.

Portable tests build a synthetic NuGet package in memory (a ZIP with the parts `dotnet pack` writes,
a .nuspec for the expected id, version, framework, license, README, repository, and commit, and a
synthetic managed PE image with a CLI header; no binary is committed), stage it, then mutate the
package and the bundle and require verification to fail. The real-package tests run when
SAS_PAIRING_NUGET_BUNDLE names a staged bundle (the Windows .NET CI job sets it, together with
SAS_PAIRING_REQUIRE_REAL_NUPKG=1 so that a missing bundle fails instead of skipping).
Run: python3 -m unittest discover -s tooling/tests -v
"""

import contextlib
import io
import json
import os
import shutil
import struct
import sys
import tempfile
import unittest
import zipfile

TOOLING = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLING)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import package_dotnet_nuget as tool  # noqa: E402
from test_package_dart_native import synthetic_pe  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
REAL_BUNDLE = os.environ.get("SAS_PAIRING_NUGET_BUNDLE", "")
REQUIRE_REAL_NUPKG = os.environ.get("SAS_PAIRING_REQUIRE_REAL_NUPKG") == "1"
URL = "https://github.com/Soneka96/sas-pairing"


def managed_pe(marker=b"SasPairing", magic=0x10B, clr=True):
    """A minimal PE image whose CLI (COR20) data directory is set: a managed assembly to the verifier."""
    image = bytearray(0x400)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    optional_size = 224 if magic == 0x10B else 240
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, optional_size, 0x2022)
    optional = 0x98
    struct.pack_into("<H", image, optional, magic)
    directories = optional + (96 if magic == 0x10B else 112)
    struct.pack_into("<I", image, directories - 4, 16)
    if clr:
        struct.pack_into("<II", image, directories + 14 * 8, 0x2008, 0x48)
    return bytes(image) + marker


def nuspec(id_="SasPairing", version="0.1.0-dev.1", tfm="net10.0", license_="MIT OR Apache-2.0",
           commit=SHA, url=URL, dependencies="", extra_metadata="", readme="README.md",
           description="Experimental, pre-alpha .NET wrapper. The native library is not included."):
    return f"""﻿<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2012/06/nuspec.xsd">
  <metadata>
    <id>{id_}</id>
    <version>{version}</version>
    <authors>sas-pairing contributors</authors>
    <license type="expression">{license_}</license>
    <licenseUrl>https://licenses.nuget.org/MIT%20OR%20Apache-2.0</licenseUrl>
    <readme>{readme}</readme>
    <projectUrl>{URL}</projectUrl>
    <description>{description}</description>
    <copyright>sas-pairing contributors</copyright>
    <repository type="git" url="{url}" branch="refs/heads/feature/p9-dotnet-package" commit="{commit}" />
    <dependencies>
      <group targetFramework="{tfm}">{dependencies}</group>
    </dependencies>{extra_metadata}
  </metadata>
</package>
""".encode("utf-8")


def documentation(name="SasPairing"):
    return f'<?xml version="1.0"?><doc><assembly><name>{name}</name></assembly><members /></doc>'.encode()


def package_readme():
    with open(tool.native.repository_file(tool.PACKAGE_README), "rb") as handle:
        return handle.read()


def entries(**overrides):
    """The parts of a valid SasPairing package; an override of None removes a part."""
    parts = {
        "_rels/.rels": b"<Relationships />",
        "SasPairing.nuspec": nuspec(),
        "README.md": package_readme(),
        "lib/net10.0/SasPairing.dll": managed_pe(),
        "lib/net10.0/SasPairing.xml": documentation(),
        "[Content_Types].xml": b"<Types />",
        "package/services/metadata/core-properties/0a1b2c3d4e.psmdcp": b"<coreProperties />",
    }
    for name, value in overrides.items():
        parts.pop(name, None) if value is None else parts.__setitem__(name, value)
    return parts


def nupkg_bytes(parts):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in parts.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="sas-pairing-dotnet-nuget-")
        self.addCleanup(shutil.rmtree, self.work, True)
        self.pack = os.path.join(self.work, "pack", tool.nupkg_file_name())
        self.built = os.path.join(self.work, "build", "SasPairing.dll")
        self.bundle = os.path.join(self.work, "dist", tool.BUNDLE_NAME)
        os.makedirs(os.path.dirname(self.built))
        with open(self.built, "wb") as handle:
            handle.write(managed_pe())

    def write_pack(self, parts=None):
        os.makedirs(os.path.dirname(self.pack), exist_ok=True)
        with open(self.pack, "wb") as handle:
            handle.write(nupkg_bytes(entries() if parts is None else parts))

    def stage(self, parts=None, sha=SHA):
        self.write_pack(parts)
        return tool.stage(self.pack, self.bundle, sha, [self.built])

    def path(self, name):
        return os.path.join(self.bundle, name)

    def read(self, name):
        with open(self.path(name), "rb") as handle:
            return handle.read()

    def write(self, name, data):
        with open(self.path(name), "wb") as handle:
            handle.write(data)

    def manifest(self):
        return json.loads(self.read(tool.MANIFEST_FILE))

    def refresh(self, manifest=None):
        """Makes the bundle metadata consistent with its (possibly replaced) package."""
        data = self.read(tool.nupkg_file_name())
        manifest = dict(manifest or self.manifest(), nupkg_sha256=tool.native.sha256_bytes(data))
        self.write(tool.MANIFEST_FILE, tool.native.manifest_bytes(manifest))
        with contextlib.suppress(KeyError):  # a manifest missing a field keeps the previous README
            self.write(tool.README_FILE, tool.readme_markdown(manifest).encode())
        self.write(tool.SUMS_FILE, tool.native.sums_text(self.bundle, tool.bundle_files()).encode())

    def replace_package(self, parts):
        self.write(tool.nupkg_file_name(), nupkg_bytes(parts))
        self.refresh()

    def assert_fails(self, needle, sha=SHA, assemblies=None):
        problems = tool.verify(self.bundle, sha, [self.built] if assemblies is None else assemblies)
        self.assertTrue(problems, "verify accepted a bad bundle")
        self.assertTrue(any(needle in problem for problem in problems), f"no problem mentions {needle!r}: {problems}")

    def assert_package_fails(self, needle, parts, sha=SHA):
        problems = tool.check_nupkg(nupkg_bytes(parts), sha, [self.built])
        self.assertTrue(any(needle in problem for problem in problems), f"no problem mentions {needle!r}: {problems}")


class HappyPath(BundleCase):
    def test_a_staged_bundle_is_exactly_the_contract_and_verifies(self):
        manifest = self.stage()
        self.assertEqual(
            sorted(os.listdir(self.bundle)),
            ["ARTIFACT-MANIFEST.json", "README.md", "SHA256SUMS.txt", "SasPairing.0.1.0-dev.1.nupkg"],
        )
        self.assertEqual(tool.verify(self.bundle, SHA, [self.built]), [])
        with open(self.pack, "rb") as handle:
            packed = handle.read()
        self.assertEqual(self.read(tool.nupkg_file_name()), packed)
        self.assertEqual(
            manifest,
            {
                "assembly_sha256": tool.native.sha256_bytes(managed_pe()),
                "bundle_name": "sas-pairing-dotnet-nuget",
                "git_commit": SHA,
                "native_bundle_name": "sas-pairing-dotnet-windows-x64-abi1",
                "native_library_bundled": False,
                "nupkg_file": "SasPairing.0.1.0-dev.1.nupkg",
                "nupkg_sha256": tool.native.sha256_bytes(packed),
                "package_id": "SasPairing",
                "package_version": "0.1.0-dev.1",
                "published_to_nuget": False,
                "schema_version": 1,
                "security_status": "experimental-pre-alpha",
                "target_framework": "net10.0",
            },
        )
        self.assertEqual(self.manifest(), manifest)
        self.assertNotIn(b"\r", self.read(tool.MANIFEST_FILE))

    def test_the_package_values_come_from_the_project(self):
        self.assertEqual(tool.package_id(), "SasPairing")
        self.assertEqual(tool.package_version(), "0.1.0-dev.1")
        self.assertEqual(tool.target_framework(), "net10.0")
        self.assertEqual(tool.license_expression(), "MIT OR Apache-2.0")
        self.assertEqual(tool.repository_url(), URL)
        self.assertEqual(tool.assembly_entry(), "lib/net10.0/SasPairing.dll")

    def test_checksums_cover_the_package_readme_and_manifest(self):
        self.stage()
        lines = self.read(tool.SUMS_FILE).decode().splitlines()
        listed = dict(reversed(line.split("  ", 1)) for line in lines)
        self.assertEqual(sorted(listed), ["ARTIFACT-MANIFEST.json", "README.md", "SasPairing.0.1.0-dev.1.nupkg"])
        self.assertEqual(listed[tool.nupkg_file_name()], self.manifest()["nupkg_sha256"])

    def test_the_readme_states_the_required_facts(self):
        self.stage()
        readme = self.read(tool.README_FILE).decode()
        for phrase in tool.README_REQUIRED + (SHA, "sas-pairing-dotnet-windows-x64-abi1-" + SHA, "SasPairingRuntime.Create(nativeLibraryPath)"):
            self.assertIn(phrase, readme)
        self.assertEqual(tool.verify_readme(self.bundle, self.manifest()), [])

    def test_the_managed_check_tells_an_assembly_from_a_native_dll(self):
        self.assertTrue(tool.is_managed_assembly(managed_pe()))
        self.assertTrue(tool.is_managed_assembly(managed_pe(magic=0x20B)))
        self.assertFalse(tool.is_managed_assembly(managed_pe(clr=False)))
        self.assertFalse(tool.is_managed_assembly(synthetic_pe()))
        self.assertFalse(tool.is_managed_assembly(b"\x7fELF" + bytes(300)))


class StageRefusals(BundleCase):
    def test_a_bad_package_commit_name_or_output_is_refused(self):
        with self.assertRaises(tool.PackagingError):
            self.stage(parts=entries(**{"runtimes/win-x64/native/sas_pairing_core.dll": synthetic_pe()}))
        self.assertFalse(os.path.exists(self.bundle))
        for sha in ("24cb89d", SHA.upper(), "latest"):
            with self.assertRaises(tool.PackagingError):
                self.stage(sha=sha)
        renamed = os.path.join(self.work, "pack", "SasPairing.nupkg")
        self.write_pack()
        shutil.copyfile(self.pack, renamed)
        with self.assertRaises(tool.PackagingError):
            tool.stage(renamed, self.bundle, SHA)
        os.makedirs(self.bundle)
        with open(self.path("stale.txt"), "wb") as handle:
            handle.write(b"x")
        with self.assertRaises(tool.PackagingError):
            tool.stage(self.pack, self.bundle, SHA)


class PackageMutations(BundleCase):
    """Each mutation of the package itself must fail (consistent outer metadata, so only the package check can)."""

    def setUp(self):
        super().setUp()
        self.stage()
        self.assertEqual(tool.verify(self.bundle, SHA, [self.built]), [])

    # B: the package hash.
    def test_a_corrupted_package_or_checksum_fails(self):
        data = bytearray(self.read(tool.nupkg_file_name()))
        data[-30] ^= 0x01
        self.write(tool.nupkg_file_name(), bytes(data))
        self.assert_fails("SHA-256 mismatch for SasPairing.0.1.0-dev.1.nupkg")
        self.assert_fails("does not equal nupkg_sha256")
        self.refresh()
        sums = self.read(tool.SUMS_FILE).decode()
        digest = self.manifest()["nupkg_sha256"]
        self.write(tool.SUMS_FILE, sums.replace(digest, ("0" if digest[0] != "0" else "1") + digest[1:]).encode())
        self.assert_fails("SHA-256 mismatch for SasPairing.0.1.0-dev.1.nupkg")

    # C: the commit, in the nuspec and in the manifest.
    def test_another_commit_fails(self):
        self.replace_package(entries(**{"SasPairing.nuspec": nuspec(commit=OTHER_SHA)}))
        self.assert_fails("repository commit is")
        self.replace_package(entries(**{"SasPairing.nuspec": nuspec(commit="")}))
        self.assert_fails("repository commit is")
        self.replace_package(entries())
        self.refresh(dict(self.manifest(), git_commit=OTHER_SHA))
        self.assert_fails("git_commit is")
        self.refresh(dict(self.manifest(), git_commit=SHA))
        self.assert_fails("repository commit is", sha=OTHER_SHA)

    # D: the version.
    def test_another_version_fails(self):
        for version in ("0.1.0-dev.2", "0.1.0", "1.0.0", "0.2.0"):
            with self.subTest(version=version):
                self.assert_package_fails("<version> is", entries(**{"SasPairing.nuspec": nuspec(version=version)}))
        self.refresh(dict(self.manifest(), package_version="0.1.0"))
        self.assert_fails("package_version is")

    # E: the target framework.
    def test_another_target_framework_fails(self):
        for tfm in ("net9.0", "net8.0", "netstandard2.0", "net10.0-windows"):
            with self.subTest(tfm=tfm):
                parts = entries(**{"SasPairing.nuspec": nuspec(tfm=tfm), "lib/net10.0/SasPairing.dll": None,
                                   "lib/net10.0/SasPairing.xml": None, f"lib/{tfm}/SasPairing.dll": managed_pe(),
                                   f"lib/{tfm}/SasPairing.xml": documentation()})
                self.assert_package_fails("the dependency group targets", parts)
                self.assert_package_fails("missing the managed assembly", parts)
                self.assert_package_fails(f"lib/{tfm}/SasPairing.dll", parts)
        self.refresh(dict(self.manifest(), target_framework="net9.0"))
        self.assert_fails("target_framework is")

    # F: a native library inside the package.
    def test_a_native_binary_or_platform_asset_fails(self):
        for name, data in (
            ("runtimes/win-x64/native/sas_pairing_core.dll", synthetic_pe()),
            ("runtimes/linux-x64/native/libsas_pairing_core.so", b"\x7fELF"),
            ("lib/net10.0/sas_pairing_core.dll", synthetic_pe()),
            ("sas_pairing_core.dll", synthetic_pe()),
            ("native/sas_pairing_core.dll", synthetic_pe()),
            ("build/SasPairing.targets", b"<Project />"),
            ("buildTransitive/SasPairing.props", b"<Project />"),
            ("tools/install.ps1", b"Invoke-WebRequest"),
            ("contentFiles/any/net10.0/sas_pairing_core.dll", synthetic_pe()),
            ("lib/net10.0/SasPairing.pdb", b"pdb"),
        ):
            with self.subTest(entry=name):
                self.replace_package(entries(**{name: data}))
                self.assert_fails(name)
        # The managed assembly replaced by a native DLL of the same name.
        self.replace_package(entries(**{"lib/net10.0/SasPairing.dll": synthetic_pe()}))
        self.assert_fails("is not a managed assembly", assemblies=[])
        self.refresh(dict(self.manifest(), native_library_bundled=True))
        self.assert_fails("native_library_bundled is")

    # G: a test assembly or test dependency.
    def test_a_test_assembly_or_dependency_fails(self):
        for name in ("lib/net10.0/SasPairing.Tests.dll", "lib/net10.0/xunit.v3.core.dll",
                     "lib/net10.0/Microsoft.Testing.Platform.dll", "lib/net10.0/testhost.dll"):
            with self.subTest(entry=name):
                self.replace_package(entries(**{name: managed_pe(b"test")}))
                self.assert_fails(name)
        for dependency in ('<dependency id="xunit.v3" version="4.0.1" />',
                           '<dependency id="Microsoft.Testing.Platform" version="2.4.0" />',
                           '<dependency id="System.Memory" version="4.6.0" />'):
            with self.subTest(dependency=dependency):
                self.replace_package(entries(**{"SasPairing.nuspec": nuspec(dependencies=dependency)}))
                self.assert_fails("package dependency")

    # H: the packed assembly differs from the built and tested one.
    def test_a_packed_assembly_other_than_the_tested_build_fails(self):
        self.replace_package(entries(**{"lib/net10.0/SasPairing.dll": managed_pe(b"SasPairing-other")}))
        self.assertEqual(tool.verify(self.bundle, SHA, []), [f"{tool.MANIFEST_FILE}: assembly_sha256 does not equal the packed lib/net10.0/SasPairing.dll"])
        self.refresh(dict(self.manifest(), assembly_sha256=tool.native.sha256_bytes(managed_pe(b"SasPairing-other"))))
        self.assertEqual(tool.verify(self.bundle, SHA, []), [])
        self.assert_fails("not byte-identical to the built and tested assembly")
        self.assert_fails("no built assembly", assemblies=[os.path.join(self.work, "missing.dll")])

    def test_wrong_identity_license_readme_or_repository_metadata_fails(self):
        for parts, needle in (
            (entries(**{"SasPairing.nuspec": nuspec(id_="SasPairing.Native")}), "<id> is"),
            (entries(**{"SasPairing.nuspec": nuspec(license_="MIT")}), "license type"),
            (entries(**{"SasPairing.nuspec": nuspec(license_="Apache-2.0")}), "license type"),
            (entries(**{"SasPairing.nuspec": nuspec(readme="docs/README.md")}), "<readme> is"),
            (entries(**{"SasPairing.nuspec": nuspec(url="https://github.com/someone/fork")}), "repository url is"),
            (entries(**{"SasPairing.nuspec": nuspec(description="A production-ready pairing library.")}), "the description does not state"),
            (entries(**{"SasPairing.nuspec": nuspec(extra_metadata="<frameworkReferences />")}), "unexpected <frameworkReferences> metadata"),
            (entries(**{"SasPairing.nuspec": nuspec(extra_metadata="<packageTypes />")}), "unexpected <packageTypes> metadata"),
            (entries(**{"SasPairing.nuspec": b"<package><metadata>"}), "not valid XML"),
            (entries(**{"README.md": b"# another README\n"}), "README.md differs from dotnet/README.md"),
            (entries(**{"README.md": None}), "missing the package README"),
            (entries(**{"lib/net10.0/SasPairing.xml": None}), "missing the XML documentation"),
            (entries(**{"lib/net10.0/SasPairing.xml": documentation("Other")}), "is not the XML documentation"),
            (entries(**{"SasPairing.nuspec": None}), "missing the nuspec"),
            (entries(**{"package/services/metadata/core-properties/0a1b2c3d4e.psmdcp": None}), "core-properties"),
            (entries(**{"notes.txt": b"x"}), "unexpected entry notes.txt"),
        ):
            with self.subTest(needle=needle):
                self.assert_package_fails(needle, parts)
        self.assertEqual(tool.check_nupkg(b"not a zip", SHA), ["nupkg: not a ZIP archive: File is not a zip file"])

    def test_the_bundle_file_set_manifest_and_readme_are_exact(self):
        for name in ("SasPairing.0.1.0-dev.1.snupkg", "sas_pairing_core.dll", "SasPairing.dll", "libsas_pairing_core.so", "notes.txt"):
            with self.subTest(file=name):
                self.write(name, b"x")
                self.assert_fails(f"unexpected file {name}")
                os.remove(self.path(name))
        for name in tool.bundle_files():
            with self.subTest(missing=name):
                original = self.read(name)
                os.remove(self.path(name))
                self.assert_fails(f"missing file {name}")
                self.write(name, original)
        original = self.manifest()
        for field, value in (("published_to_nuget", True), ("published_to_nuget", 0), ("package_id", "SasPairing.Core"),
                             ("bundle_name", "latest"), ("security_status", "production"), ("schema_version", 2),
                             ("native_bundle_name", "sas-pairing-dart-windows-x64-abi1"), ("nupkg_file", "SasPairing.nupkg")):
            with self.subTest(field=field, value=value):
                self.refresh(dict(original, **{field: value}))
                self.assert_fails(f"{field} is")
        self.refresh({k: v for k, v in original.items() if k != "assembly_sha256"})
        self.assert_fails("missing field assembly_sha256")
        self.refresh(dict(original, release="latest"))
        self.assert_fails("unknown field release")
        self.refresh(original)
        readme = self.read(tool.README_FILE).decode()
        self.write(tool.README_FILE, readme.replace("**not published to nuget.org**", "published").encode())
        self.assert_fails("not published to nuget.org")
        self.write(tool.README_FILE, (readme + "\nThis package is published to nuget.org.\n").encode())
        self.assert_fails("false claim 'published to nuget.org'")
        self.write(tool.README_FILE, (readme + "\nIt is production-ready.\n").encode())
        self.assert_fails("false claim 'production-ready'")

    def test_the_command_line_reports_failure_with_exit_status_one(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ok = tool.main(["verify", "--bundle", self.bundle, "--git-sha", SHA, "--assembly", self.built])
            failed = tool.main(["verify", "--bundle", self.bundle, "--git-sha", OTHER_SHA])
        self.assertEqual((ok, failed), (0, 1))
        self.assertIn("repository commit is", output.getvalue())


@unittest.skipUnless(REQUIRE_REAL_NUPKG or REAL_BUNDLE, "SAS_PAIRING_NUGET_BUNDLE does not name a staged bundle")
class RealNupkg(unittest.TestCase):
    """The real staged CI bundle: the package `dotnet pack` produced from this commit's Release build."""

    def setUp(self):
        if not REAL_BUNDLE or not os.path.isdir(REAL_BUNDLE):
            self.fail(f"SAS_PAIRING_NUGET_BUNDLE must name the staged {tool.BUNDLE_NAME}: {REAL_BUNDLE!r}")
        with open(os.path.join(REAL_BUNDLE, tool.MANIFEST_FILE), "rb") as handle:
            self.manifest = json.loads(handle.read())
        self.sha = self.manifest["git_commit"]
        with open(os.path.join(REAL_BUNDLE, tool.nupkg_file_name()), "rb") as handle:
            self.data = handle.read()

    def test_the_real_bundle_verifies_for_its_commit_and_this_checkout(self):
        if os.environ.get("GITHUB_SHA"):
            self.assertEqual(self.sha, os.environ["GITHUB_SHA"])
        self.assertEqual(tool.verify(REAL_BUNDLE, self.sha), [])
        self.assertTrue(tool.verify(REAL_BUNDLE, OTHER_SHA))

    def test_the_real_package_has_exactly_the_managed_parts_and_no_native_binary(self):
        with zipfile.ZipFile(io.BytesIO(self.data)) as archive:
            names = sorted(archive.namelist())
            assembly = archive.read("lib/net10.0/SasPairing.dll")
        self.assertEqual([n for n in names if not n.startswith("package/")],
                         ["README.md", "SasPairing.nuspec", "[Content_Types].xml", "_rels/.rels",
                          "lib/net10.0/SasPairing.dll", "lib/net10.0/SasPairing.xml"])
        self.assertFalse([n for n in names if n.startswith("runtimes/") or n.lower().endswith((".so", ".pdb", ".exe"))])
        self.assertEqual([n for n in names if n.lower().endswith(".dll")], ["lib/net10.0/SasPairing.dll"])
        self.assertTrue(tool.is_managed_assembly(assembly))
        self.assertEqual(tool.native.sha256_bytes(assembly), self.manifest["assembly_sha256"])

    def test_a_native_dll_injected_into_the_real_package_fails(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.data)) as source, zipfile.ZipFile(buffer, "w") as target:
            for info in source.infolist():
                target.writestr(info, source.read(info))
            target.writestr("runtimes/win-x64/native/sas_pairing_core.dll", synthetic_pe())
        problems = tool.check_nupkg(buffer.getvalue(), self.sha)
        self.assertTrue(any("runtimes/win-x64/native/sas_pairing_core.dll" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
