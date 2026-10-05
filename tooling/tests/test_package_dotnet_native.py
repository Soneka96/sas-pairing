"""Tests of tooling/package_dotnet_native.py, the P9-D-006 Windows x64 native bundle stager and verifier.

Portable tests stage a synthetic PE32+ image (built in memory by the P8 tests' helper; no binary is
committed) whose export table lists the 25 manifest exports, then mutate the bundle and require
`verify` to fail. The real-DLL tests run when SAS_PAIRING_NATIVE_LIBRARY names the built Windows
artifact (the Windows .NET CI job sets it, together with SAS_PAIRING_REQUIRE_REAL_DLL=1 so that a
missing library fails instead of skipping). Run: python3 -m unittest discover -s tooling/tests -v
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

TOOLING = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOLING)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import package_dart_native  # noqa: E402
import package_dotnet_native as tool  # noqa: E402
from test_package_dart_native import fixture_metadata, synthetic_pe  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
REAL_DLL = os.environ.get("SAS_PAIRING_NATIVE_LIBRARY", "")
REQUIRE_REAL_DLL = os.environ.get("SAS_PAIRING_REQUIRE_REAL_DLL") == "1"


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="sas-pairing-dotnet-native-")
        self.addCleanup(shutil.rmtree, self.work, True)
        self.build = os.path.join(self.work, "build", tool.LIBRARY_FILE)
        self.bundle = os.path.join(self.work, "dist", tool.BUNDLE_NAME)

    def write_library(self, data):
        os.makedirs(os.path.dirname(self.build), exist_ok=True)
        with open(self.build, "wb") as handle:
            handle.write(data)

    def stage(self, data=None, sha=SHA, target=tool.RUST_TARGET, metadata=None):
        self.write_library(synthetic_pe() if data is None else data)
        return tool.stage(self.build, self.bundle, sha, target, metadata or fixture_metadata())

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

    def write_manifest(self, manifest, refresh_sums=True):
        self.write(tool.MANIFEST_FILE, tool.manifest_bytes(manifest))
        if refresh_sums:
            self.write(tool.SUMS_FILE, tool.sums_text(self.bundle, tool.BUNDLE_FILES).encode())

    def assert_fails(self, needle, sha=SHA, source_library=None):
        problems = tool.verify(self.bundle, sha, source_library)
        self.assertTrue(problems, "verify accepted a bad bundle")
        self.assertTrue(
            any(needle in problem for problem in problems),
            f"no problem mentions {needle!r}: {problems}",
        )


class HappyPath(BundleCase):
    def test_a_staged_bundle_is_exactly_the_contract_and_verifies(self):
        manifest = self.stage()
        self.assertEqual(sorted(os.listdir(self.bundle)), sorted(tool.BUNDLE_FILES))
        self.assertEqual(
            tool.BUNDLE_FILES,
            ("ARTIFACT-MANIFEST.json", "LICENSE-APACHE", "LICENSE-MIT", "README.md", "SHA256SUMS.txt",
             "THIRD-PARTY-NOTICES.md", "abi-v1-manifest.md", "sas_pairing.h", "sas_pairing_core.dll"),
        )
        self.assertEqual(tool.verify(self.bundle, SHA), [])
        self.assertEqual(tool.verify(self.bundle, SHA, self.build), [])
        self.assertEqual(
            manifest,
            {
                "abi_version": 1,
                "architecture": "x86_64",
                "bundle_name": "sas-pairing-dotnet-windows-x64-abi1",
                "code_signed": False,
                "core_crate_version": tool.core_crate_version(),
                "dotnet_package_version": tool.dotnet_package_version(),
                "export_count": 25,
                "git_commit": SHA,
                "library_file": "sas_pairing_core.dll",
                "library_sha256": tool.sha256_file(self.build),
                "platform": "windows",
                "rust_target": "x86_64-pc-windows-msvc",
                "schema_version": 1,
                "security_status": "experimental-pre-alpha",
            },
        )
        self.assertEqual(self.manifest(), manifest)

    def test_the_versions_come_from_the_repository(self):
        self.assertEqual(tool.dotnet_package_version(), "0.1.0-dev.1")
        self.assertEqual(tool.dotnet_target_framework(), "net10.0")
        self.assertEqual(tool.core_crate_version(), "0.1.0")
        self.assertEqual(tool.header_abi_version(), 1)
        self.assertEqual(len(tool.manifest_export_names()), 25)

    def test_the_staged_dll_is_a_byte_for_byte_copy_and_the_checksums_match(self):
        self.stage()
        with open(self.build, "rb") as handle:
            self.assertEqual(self.read(tool.LIBRARY_FILE), handle.read())
        lines = self.read(tool.SUMS_FILE).decode().splitlines()
        listed = dict(reversed(line.split("  ", 1)) for line in lines)
        self.assertEqual(sorted(listed), [name for name in tool.BUNDLE_FILES if name != tool.SUMS_FILE])
        self.assertEqual(listed[tool.LIBRARY_FILE], self.manifest()["library_sha256"])
        for name, digest in listed.items():
            self.assertEqual(tool.sha256_file(self.path(name)), digest, name)

    def test_copied_files_are_unchanged_repository_files_and_the_manifest_is_deterministic(self):
        self.stage()
        for name, relative in tool.COPIED_FILES.items():
            with open(tool.repository_file(relative), "rb") as handle:
                self.assertEqual(self.read(name), handle.read(), name)
        first = self.read(tool.MANIFEST_FILE)
        shutil.rmtree(self.bundle)
        self.stage()
        self.assertEqual(self.read(tool.MANIFEST_FILE), first)
        self.assertNotIn(b"\r", first)

    def test_notices_and_readme_state_the_required_facts(self):
        self.stage()
        notices = self.read(tool.NOTICES_FILE).decode()
        self.assertIn("| alpha | 1.2.3 | MIT OR Apache-2.0 | normal |", notices)
        self.assertNotIn("testonly", notices)
        self.assertIn("tooling/package_dotnet_native.py", notices)
        self.assertIn("not legal advice", notices)
        readme = self.read(tool.README_FILE).decode()
        for phrase in tool.README_REQUIRED + (SHA, "SasPairingRuntime.Create(nativeLibraryPath)", "sas-pairing-dotnet-nuget-" + SHA):
            self.assertIn(phrase, readme)

    def test_the_p8_tool_and_its_bundle_contract_are_unchanged(self):
        # P9-D-006: the P8 tool is reused by import only; its own bundle name and Dart-version field stand.
        self.assertEqual(package_dart_native.BUNDLE_NAME, "sas-pairing-dart-windows-x64-abi1")
        self.assertIn("dart_package_version", package_dart_native.MANIFEST_FIELDS)
        self.assertNotIn("dotnet_package_version", package_dart_native.MANIFEST_FIELDS)
        self.assertNotIn("dart_package_version", tool.MANIFEST_FIELDS)
        self.assertNotEqual(tool.BUNDLE_NAME, package_dart_native.BUNDLE_NAME)


class StageRefusals(BundleCase):
    def assert_stage_refused(self, needle, **kwargs):
        with self.assertRaises(tool.PackagingError) as raised:
            self.stage(**kwargs)
        self.assertIn(needle, str(raised.exception))

    def test_another_rust_target_is_refused(self):
        for target in ("aarch64-pc-windows-msvc", "i686-pc-windows-msvc", "x86_64-unknown-linux-gnu"):
            self.assert_stage_refused("only Windows x64", target=target)
        self.assertFalse(os.path.exists(self.bundle))

    def test_a_short_or_mutable_commit_is_refused(self):
        for sha in ("deaa586", SHA.upper(), "latest", "current", "release"):
            self.assert_stage_refused("40-hex-digit", sha=sha)

    def test_a_package_without_license_metadata_stops_packaging(self):
        with self.assertRaises(tool.PackagingError) as raised:
            self.stage(metadata=fixture_metadata(license_expression=None))
        self.assertIn("STOP: alpha 1.2.3 has no license metadata", str(raised.exception))
        self.assertFalse(os.path.exists(self.bundle))

    def test_staging_an_arm64_x86_or_malformed_dll_or_a_wrong_export_set_is_refused(self):
        for data in (synthetic_pe(machine=0xAA64), synthetic_pe(machine=0x14C), synthetic_pe(magic=0x10B), b"\x7fELF" + bytes(200)):
            with self.subTest(data=data[:8]):
                with self.assertRaises(tool.PackagingError):
                    self.stage(data=data)
                self.assertFalse(os.path.exists(self.bundle))
        names = tool.manifest_export_names()
        self.assert_stage_refused("missing export sas_pairing_run_cancel_sas", data=synthetic_pe(
            exports=[n for n in names if n != "sas_pairing_run_cancel_sas"]))
        self.assert_stage_refused("unexpected export sas_pairing_reset", data=synthetic_pe(exports=names + ["sas_pairing_reset"]))


class VerifyMutations(BundleCase):
    def setUp(self):
        super().setUp()
        self.stage()
        self.assertEqual(tool.verify(self.bundle, SHA), [])

    # I: the native DLL hash.
    def test_one_changed_dll_byte_fails(self):
        data = bytearray(self.read(tool.LIBRARY_FILE))
        data[-1] ^= 0x01
        self.write(tool.LIBRARY_FILE, bytes(data))
        self.assert_fails("SHA-256 mismatch for sas_pairing_core.dll")
        self.assert_fails("does not equal library_sha256")

    # I: the staged DLL differs from the tested build DLL, even with consistent metadata.
    def test_a_staged_dll_differing_from_the_source_by_one_byte_fails(self):
        data = bytearray(self.read(tool.LIBRARY_FILE))
        data[0x10] ^= 0xFF  # an unused DOS-header byte: still a valid AMD64 DLL
        self.write(tool.LIBRARY_FILE, bytes(data))
        manifest = self.manifest()
        manifest["library_sha256"] = tool.sha256_file(self.path(tool.LIBRARY_FILE))
        self.write_manifest(manifest)
        self.write(tool.README_FILE, tool.readme_markdown(manifest).encode())
        self.write(tool.SUMS_FILE, tool.sums_text(self.bundle, tool.BUNDLE_FILES).encode())
        self.assertEqual(tool.verify(self.bundle, SHA), [])
        self.assert_fails("not byte-identical to the source library", source_library=self.build)

    # J: another PE machine, even with matching metadata.
    def test_a_staged_dll_of_another_machine_fails(self):
        for machine, name in ((0xAA64, "ARM64"), (0x14C, "x86"), (0xA641, "ARM64EC")):
            with self.subTest(machine=name):
                self.write(tool.LIBRARY_FILE, synthetic_pe(machine=machine))
                manifest = self.manifest()
                manifest["library_sha256"] = tool.sha256_file(self.path(tool.LIBRARY_FILE))
                self.write_manifest(manifest)
                self.assert_fails("is not AMD64")

    # The export set (with consistent metadata).
    def test_a_missing_or_extra_export_fails(self):
        names = tool.manifest_export_names()
        for exports, needle in (
            ([n for n in names if n != "sas_pairing_result_copy"], "missing export sas_pairing_result_copy"),
            (names + ["sas_pairing_reload"], "unexpected export sas_pairing_reload"),
        ):
            with self.subTest(needle=needle):
                self.write(tool.LIBRARY_FILE, synthetic_pe(exports=exports))
                manifest = self.manifest()
                manifest["library_sha256"] = tool.sha256_file(self.path(tool.LIBRARY_FILE))
                self.write_manifest(manifest)
                self.assert_fails(needle)

    def test_wrong_commit_abi_exports_platform_version_or_signing_fails(self):
        for field, value in (
            ("git_commit", OTHER_SHA),
            ("abi_version", 2),
            ("abi_version", True),
            ("export_count", 24),
            ("platform", "linux"),
            ("architecture", "aarch64"),
            ("rust_target", "aarch64-pc-windows-msvc"),
            ("dotnet_package_version", "1.0.0"),
            ("dotnet_package_version", "0.1.0"),
            ("bundle_name", "sas-pairing-dart-windows-x64-abi1"),
            ("security_status", "production"),
            ("library_file", "libsas_pairing_core.so"),
            ("code_signed", True),
        ):
            with self.subTest(field=field, value=value):
                manifest = self.manifest()
                manifest[field] = value
                self.write_manifest(manifest)
                self.assert_fails(f"{field} is")
        self.write_manifest(dict(self.manifest(), git_commit=SHA))
        self.assert_fails("git_commit is", sha=OTHER_SHA)

    def test_missing_unknown_or_unformatted_manifest_fields_fail(self):
        original = self.manifest()
        self.write_manifest({k: v for k, v in original.items() if k != "dotnet_package_version"})
        self.assert_fails("missing field dotnet_package_version")
        self.write_manifest(dict(original, dart_package_version="0.1.0-dev.1"))
        self.assert_fails("unknown field dart_package_version")
        self.write(tool.MANIFEST_FILE, json.dumps(original).encode())
        self.assert_fails("deterministic form")

    # K: a missing or changed license or notices.
    def test_a_missing_or_changed_license_or_notices_fails(self):
        for name in ("LICENSE-MIT", "LICENSE-APACHE", tool.NOTICES_FILE):
            with self.subTest(file=name):
                original = self.read(name)
                os.remove(self.path(name))
                self.assert_fails(f"missing file {name}")
                self.write(name, original)
        self.write("LICENSE-MIT", self.read("LICENSE-MIT").replace(b"MIT", b"BSD", 1))
        self.assert_fails("LICENSE-MIT: differs from the repository")

    # L: an extra binary or build file.
    def test_extra_binaries_and_build_files_fail(self):
        for name in ("debug.pdb", "extra.dll", "libsas_pairing_core.so", "sas_pairing_core.lib",
                     "sas_pairing_core.exp", "sas_pairing_core.ilk", "SasPairing.0.1.0-dev.1.nupkg", "smoke.exe"):
            with self.subTest(file=name):
                self.write(name, b"x")
                self.assert_fails(f"unexpected file {name}")
                os.remove(self.path(name))
        os.makedirs(self.path("target"))
        self.assert_fails("unexpected directory target/")

    def test_a_readme_signing_or_production_claim_fails(self):
        readme = self.read(tool.README_FILE).decode()
        self.write(tool.README_FILE, readme.replace("**not code-signed**", "**code-signed**").encode())
        self.assert_fails("missing statement '**not code-signed**'")
        self.write(tool.README_FILE, (readme + "\nThe DLL is code-signed.\n").encode())
        self.assert_fails("false claim 'is code-signed'")
        self.write(tool.README_FILE, readme.replace("not a digital signature", "a digital signature").encode())
        self.assert_fails("not a digital signature")
        self.write(tool.README_FILE, readme.replace("contains no native library", "bundles it").encode())
        self.assert_fails("contains no native library")

    def test_the_command_line_reports_failure_with_exit_status_one(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ok = tool.main(["verify", "--bundle", self.bundle, "--git-sha", SHA, "--source-library", self.build])
            self.write("debug.pdb", b"x")
            failed = tool.main(["verify", "--bundle", self.bundle, "--git-sha", SHA])
        self.assertEqual((ok, failed), (0, 1))
        self.assertIn("unexpected file debug.pdb", output.getvalue())


@unittest.skipUnless(
    REQUIRE_REAL_DLL or REAL_DLL.endswith(tool.LIBRARY_FILE),
    "SAS_PAIRING_NATIVE_LIBRARY does not name the Windows sas_pairing_core.dll",
)
class DotnetRealWindowsDll(BundleCase):
    """The real CI artifact: an AMD64 PE32+ DLL with exactly the 25 exports, staged into a .NET bundle."""

    def real_bytes(self):
        if not REAL_DLL or not REAL_DLL.endswith(tool.LIBRARY_FILE) or not os.path.isfile(REAL_DLL):
            self.fail(f"SAS_PAIRING_NATIVE_LIBRARY must name the built {tool.LIBRARY_FILE}: {REAL_DLL!r}")
        with open(REAL_DLL, "rb") as handle:
            return handle.read()

    def test_the_real_dll_stages_verifies_and_rejects_another_machine(self):
        data = self.real_bytes()
        self.assertEqual(tool.check_amd64_dll(data), "AMD64 (x86_64)")
        self.assertEqual(tool.check_exports(data), 25)
        self.stage(data=data)
        self.assertEqual(tool.verify(self.bundle, SHA, self.build), [])
        self.assertEqual(self.manifest()["library_sha256"], tool.sha256_bytes(data))
        mutated = bytearray(data)
        (pe_offset,) = struct.unpack_from("<I", mutated, 0x3C)
        struct.pack_into("<H", mutated, pe_offset + 4, 0xAA64)
        with self.assertRaises(tool.PackagingError):
            tool.check_amd64_dll(bytes(mutated))


if __name__ == "__main__":
    unittest.main()
