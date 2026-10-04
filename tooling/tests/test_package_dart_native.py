"""Tests of tooling/package_dart_native.py, the P8-D-006 Windows x64 bundle stager and verifier.

Portable tests stage a synthetic PE32+ image (built in memory; no binary is committed) whose
export table lists the 25 manifest exports, then mutate the bundle and require `verify` to fail.
The real-DLL tests run when SAS_PAIRING_NATIVE_LIBRARY names the built Windows artifact (the
Windows Dart CI job sets it, together with SAS_PAIRING_REQUIRE_REAL_DLL=1 so that a missing
library fails instead of skipping). Run: python3 -m unittest discover -s tooling/tests -v
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

import package_dart_native as tool  # noqa: E402

SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
REAL_DLL = os.environ.get("SAS_PAIRING_NATIVE_LIBRARY", "")
REQUIRE_REAL_DLL = os.environ.get("SAS_PAIRING_REQUIRE_REAL_DLL") == "1"


def synthetic_pe(machine=0x8664, magic=0x20B, dll=True, exports=None):
    """A minimal PE image: DOS header, COFF header, optional header, one section holding an
    export directory with [exports] (default: the 25 ABI v1 manifest exports)."""
    names = tool.manifest_export_names() if exports is None else exports
    section_rva, section_raw = 0x1000, 0x200
    directory = bytearray(40)
    names_rva = section_rva + 40
    strings_rva = names_rva + 4 * len(names)
    pointers, strings = bytearray(), bytearray()
    for name in names:
        pointers += struct.pack("<I", strings_rva + len(strings))
        strings += name.encode("ascii") + b"\0"
    struct.pack_into("<II", directory, 20, len(names), len(names))  # functions, names
    struct.pack_into("<I", directory, 32, names_rva)
    section = bytes(directory + pointers + strings)

    image = bytearray(section_raw)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\0\0"
    characteristics = 0x0022 | (0x2000 if dll else 0)
    struct.pack_into("<HHIIIHH", image, 0x44, machine, 1, 0, 0, 0, 240, characteristics)
    optional = 0x58
    struct.pack_into("<H", image, optional, magic)
    struct.pack_into("<II", image, optional + 112, section_rva, len(section))
    header = optional + 240
    image[header : header + 8] = b".edata\0\0"
    struct.pack_into("<IIII", image, header + 8, len(section), section_rva, len(section), section_raw)
    return bytes(image) + section


def fixture_metadata(license_expression="MIT OR Apache-2.0"):
    """`cargo metadata`-shaped JSON: a root with a normal, a build, and a dev-only dependency."""

    def package(name, version, license_value, repository):
        return {
            "id": f"{name} {version}",
            "name": name,
            "version": version,
            "license": license_value,
            "repository": repository,
            "source": "registry+https://github.com/rust-lang/crates.io-index",
        }

    def edge(pkg, kind):
        return {"pkg": pkg, "dep_kinds": [{"kind": kind, "target": None}]}

    return {
        "packages": [
            package("sas-pairing-core", "0.1.0", None, None),
            package("alpha", "1.2.3", license_expression, "https://example.invalid/alpha"),
            package("builder", "0.4.0", "Apache-2.0", None),
            package("testonly", "9.9.9", None, None),
            package("leaf", "2.0.0", "BSD-3-Clause", "https://example.invalid/leaf"),
        ],
        "resolve": {
            "root": "sas-pairing-core 0.1.0",
            "nodes": [
                {
                    "id": "sas-pairing-core 0.1.0",
                    "deps": [
                        edge("alpha 1.2.3", None),
                        edge("builder 0.4.0", "build"),
                        edge("testonly 9.9.9", "dev"),
                    ],
                },
                {"id": "alpha 1.2.3", "deps": [edge("leaf 2.0.0", None)]},
                {"id": "builder 0.4.0", "deps": []},
                {"id": "testonly 9.9.9", "deps": []},
                {"id": "leaf 2.0.0", "deps": []},
            ],
        },
    }


class BundleCase(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp(prefix="sas-pairing-bundle-")
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
            self.write(tool.SUMS_FILE, tool.sums_text(self.bundle).encode())

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
        self.assertEqual(len(tool.BUNDLE_FILES), 9)
        self.assertEqual(tool.verify(self.bundle, SHA), [])
        self.assertEqual(tool.verify(self.bundle, SHA, self.build), [])
        self.assertEqual(self.manifest(), manifest)
        self.assertEqual(
            manifest,
            {
                "abi_version": 1,
                "architecture": "x86_64",
                "bundle_name": "sas-pairing-dart-windows-x64-abi1",
                "code_signed": False,
                "core_crate_version": tool.core_crate_version(),
                "dart_package_version": tool.dart_package_version(),
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

    def test_the_versions_come_from_the_repository(self):
        self.assertEqual(tool.dart_package_version(), "0.1.0-dev.1")
        self.assertEqual(tool.core_crate_version(), "0.1.0")
        self.assertEqual(tool.header_abi_version(), 1)
        self.assertEqual(len(tool.manifest_export_names()), 25)

    def test_the_staged_dll_is_a_byte_for_byte_copy(self):
        self.stage()
        with open(self.build, "rb") as handle:
            self.assertEqual(self.read(tool.LIBRARY_FILE), handle.read())

    def test_checksums_cover_every_other_file_and_match_the_manifest(self):
        self.stage()
        lines = self.read(tool.SUMS_FILE).decode().splitlines()
        names = [line.split("  ", 1)[1] for line in lines]
        self.assertEqual(names, [name for name in tool.BUNDLE_FILES if name != tool.SUMS_FILE])
        listed = dict(reversed(line.split("  ", 1)) for line in lines)
        self.assertEqual(listed[tool.LIBRARY_FILE], self.manifest()["library_sha256"])
        for name, digest in listed.items():
            self.assertEqual(tool.sha256_file(self.path(name)), digest, name)

    def test_copied_files_are_unchanged_repository_files(self):
        self.stage()
        for name, relative in tool.COPIED_FILES.items():
            with open(tool.repository_file(relative), "rb") as handle:
                self.assertEqual(self.read(name), handle.read(), name)

    def test_the_manifest_is_deterministic(self):
        self.stage()
        first = self.read(tool.MANIFEST_FILE)
        shutil.rmtree(self.bundle)
        self.stage()
        self.assertEqual(self.read(tool.MANIFEST_FILE), first)
        self.assertEqual(first, tool.manifest_bytes(json.loads(first)))
        self.assertNotIn(b"\r", first)

    def test_notices_list_normal_and_build_packages_but_no_dev_only_or_root(self):
        self.stage()
        notices = self.read(tool.NOTICES_FILE).decode()
        self.assertIn("| alpha | 1.2.3 | MIT OR Apache-2.0 | normal | https://example.invalid/alpha |", notices)
        self.assertIn("| leaf | 2.0.0 | BSD-3-Clause | normal | https://example.invalid/leaf |", notices)
        self.assertIn("| builder | 0.4.0 | Apache-2.0 | build | registry+", notices)
        self.assertNotIn("testonly", notices)
        self.assertNotIn("| sas-pairing-core |", notices)
        self.assertIn("Packages: 3.", notices)
        self.assertIn("not legal advice", notices)

    def test_the_readme_states_the_required_facts(self):
        self.stage()
        readme = self.read(tool.README_FILE).decode()
        for phrase in tool.README_REQUIRED + (SHA, tool.LIBRARY_FILE, "0.1.0-dev.1"):
            self.assertIn(phrase, readme)


class StageRefusals(BundleCase):
    def assert_stage_refused(self, needle, **kwargs):
        with self.assertRaises(tool.PackagingError) as raised:
            self.stage(**kwargs)
        self.assertIn(needle, str(raised.exception))

    def test_another_rust_target_is_refused(self):
        for target in ("aarch64-pc-windows-msvc", "i686-pc-windows-msvc", "x86_64-unknown-linux-gnu"):
            self.assert_stage_refused("only Windows x64", target=target)
        self.assertFalse(os.path.exists(self.bundle))

    def test_a_short_or_uppercase_commit_is_refused(self):
        for sha in ("deaa586", SHA.upper(), SHA + "0", "latest"):
            self.assert_stage_refused("40-hex-digit", sha=sha)

    def test_a_non_empty_output_is_refused(self):
        os.makedirs(self.bundle)
        self.write("stale.txt", b"x")
        self.assert_stage_refused("new or empty directory")

    def test_a_library_must_be_named_explicitly(self):
        self.write_library(synthetic_pe())
        with self.assertRaises(tool.PackagingError):
            tool.stage(os.path.dirname(self.build), self.bundle, SHA, tool.RUST_TARGET, fixture_metadata())
        renamed = os.path.join(self.work, "build", "other.dll")
        shutil.copyfile(self.build, renamed)
        with self.assertRaises(tool.PackagingError):
            tool.stage(renamed, self.bundle, SHA, tool.RUST_TARGET, fixture_metadata())

    def test_a_package_without_license_metadata_stops_packaging(self):
        for missing in (None, "", "  "):
            with self.subTest(missing=missing):
                with self.assertRaises(tool.PackagingError) as raised:
                    self.stage(metadata=fixture_metadata(license_expression=missing))
                self.assertIn("STOP: alpha 1.2.3 has no license metadata", str(raised.exception))
                self.assertFalse(os.path.exists(self.bundle))

    def test_missing_extra_or_duplicate_exports_are_refused(self):
        names = tool.manifest_export_names()
        self.assert_stage_refused("missing export sas_pairing_run_cancel_sas", data=synthetic_pe(
            exports=[n for n in names if n != "sas_pairing_run_cancel_sas"]))
        self.assert_stage_refused("unexpected export sas_pairing_reset", data=synthetic_pe(
            exports=names + ["sas_pairing_reset"]))
        self.assert_stage_refused("exported twice", data=synthetic_pe(exports=names + names[:1]))
        self.assert_stage_refused("missing export", data=synthetic_pe(exports=[]))


class Architecture(BundleCase):
    def test_only_an_amd64_pe32_plus_dll_is_accepted(self):
        self.assertEqual(tool.check_amd64_dll(synthetic_pe()), "AMD64 (x86_64)")
        for machine, name in ((0x14C, "x86"), (0xAA64, "ARM64"), (0xA641, "ARM64EC"), (0x1C4, "ARMNT"), (0x1234, "unknown")):
            with self.subTest(machine=hex(machine)):
                with self.assertRaises(tool.PackagingError) as raised:
                    tool.check_amd64_dll(synthetic_pe(machine=machine))
                self.assertIn(name, str(raised.exception))
                self.assertIn("is not AMD64", str(raised.exception))

    def test_pe32_non_dll_and_malformed_images_are_refused(self):
        cases = {
            "not PE32+": synthetic_pe(magic=0x10B),
            "not a DLL": synthetic_pe(dll=False),
            "no MZ header": b"\x7fELF" + bytes(200),
            "no PE signature": b"MZ" + bytes(0x3A) + struct.pack("<I", 0x40) + b"NE\0\0" + bytes(64),
        }
        truncated = bytearray(b"MZ" + bytes(0x3E))
        struct.pack_into("<I", truncated, 0x3C, 0x1000)
        cases["no PE signature (truncated)"] = bytes(truncated)
        for needle, data in cases.items():
            with self.subTest(case=needle):
                with self.assertRaises(tool.PackagingError) as raised:
                    tool.check_amd64_dll(data)
                self.assertIn(needle.split(" (")[0], str(raised.exception))

    def test_staging_an_arm64_or_x86_dll_is_refused(self):
        for machine in (0xAA64, 0x14C):
            with self.subTest(machine=hex(machine)):
                with self.assertRaises(tool.PackagingError):
                    self.stage(data=synthetic_pe(machine=machine))
                self.assertFalse(os.path.exists(self.bundle))

    def test_verify_rejects_a_staged_dll_of_another_machine_even_with_matching_metadata(self):
        self.stage()
        self.write(tool.LIBRARY_FILE, synthetic_pe(machine=0xAA64))
        manifest = self.manifest()
        manifest["library_sha256"] = tool.sha256_file(self.path(tool.LIBRARY_FILE))
        self.write_manifest(manifest)
        self.assert_fails("is not AMD64")


class VerifyMutations(BundleCase):
    def setUp(self):
        super().setUp()
        self.stage()
        self.assertEqual(tool.verify(self.bundle, SHA), [])

    # B: wrong DLL checksum.
    def test_one_changed_dll_byte_fails(self):
        data = bytearray(self.read(tool.LIBRARY_FILE))
        data[-1] ^= 0x01
        self.write(tool.LIBRARY_FILE, bytes(data))
        self.assert_fails("SHA-256 mismatch for sas_pairing_core.dll")
        self.assert_fails("does not equal library_sha256")

    def test_a_changed_checksum_line_fails(self):
        text = self.read(tool.SUMS_FILE).decode()
        digest = self.manifest()["library_sha256"]
        flipped = ("0" if digest[0] != "0" else "1") + digest[1:]
        self.write(tool.SUMS_FILE, text.replace(digest, flipped).encode())
        self.assert_fails("SHA-256 mismatch for sas_pairing_core.dll")

    def test_a_changed_copied_file_fails_through_its_checksum(self):
        self.write("sas_pairing.h", self.read("sas_pairing.h") + b"/* changed */\n")
        self.assert_fails("SHA-256 mismatch for sas_pairing.h")
        self.assert_fails("differs from the repository")

    def test_malformed_missing_or_extra_checksum_lines_fail(self):
        text = self.read(tool.SUMS_FILE).decode()
        self.write(tool.SUMS_FILE, text.replace("  README.md", " README.md").encode())
        self.assert_fails("malformed line")
        self.write(tool.SUMS_FILE, "".join(l + "\n" for l in text.splitlines() if not l.endswith("LICENSE-MIT")).encode())
        self.assert_fails("no checksum for LICENSE-MIT")
        self.write(tool.SUMS_FILE, (text + "0" * 64 + "  extra.txt\n").encode())
        self.assert_fails("unexpected entry extra.txt")
        self.write(tool.SUMS_FILE, text.replace("\n", "\r\n").encode())
        self.assert_fails("not LF-terminated")

    # C: wrong commit.
    def test_a_manifest_for_another_commit_fails(self):
        manifest = self.manifest()
        manifest["git_commit"] = OTHER_SHA
        self.write_manifest(manifest)
        self.assert_fails("git_commit is")

    def test_verifying_against_another_commit_fails(self):
        self.assert_fails("git_commit is", sha=OTHER_SHA)
        self.assert_fails("40-hex-digit", sha="deaa586")

    # D: wrong ABI.
    def test_another_abi_version_fails(self):
        for value in (2, 0, "1", True, 1.0):
            with self.subTest(value=value):
                manifest = self.manifest()
                manifest["abi_version"] = value
                self.write_manifest(manifest)
                self.assert_fails("abi_version is")

    def test_another_export_count_fails(self):
        for value in (24, 26, 0, "25"):
            with self.subTest(value=value):
                manifest = self.manifest()
                manifest["export_count"] = value
                self.write_manifest(manifest)
                self.assert_fails("export_count is")

    def test_another_platform_architecture_target_or_status_fails(self):
        for field, value in (
            ("platform", "linux"),
            ("architecture", "aarch64"),
            ("architecture", "x86"),
            ("rust_target", "aarch64-pc-windows-msvc"),
            ("security_status", "production"),
            ("library_file", "libsas_pairing_core.so"),
            ("bundle_name", "latest"),
            ("schema_version", 2),
            ("dart_package_version", "1.0.0"),
            ("core_crate_version", "9.9.9"),
        ):
            with self.subTest(field=field, value=value):
                manifest = self.manifest()
                manifest[field] = value
                self.write_manifest(manifest)
                self.assert_fails(f"{field} is")

    def test_missing_unknown_or_unformatted_manifest_fields_fail(self):
        original = self.manifest()
        self.write_manifest({k: v for k, v in original.items() if k != "library_sha256"})
        self.assert_fails("missing field library_sha256")
        self.write_manifest(dict(original, release="latest"))
        self.assert_fails("unknown field release")
        self.write(tool.MANIFEST_FILE, json.dumps(json.loads(self.read(tool.MANIFEST_FILE))).encode())
        self.assert_fails("deterministic form")
        self.write(tool.MANIFEST_FILE, b"{not json")
        self.assert_fails("not valid JSON")

    # K: false code-signing claim.
    def test_a_code_signed_claim_fails(self):
        for value in (True, "false", 0, None):
            with self.subTest(value=value):
                manifest = self.manifest()
                manifest["code_signed"] = value
                self.write_manifest(manifest)
                self.assert_fails("code_signed is")

    def test_a_readme_signing_or_production_claim_fails(self):
        readme = self.read(tool.README_FILE).decode()
        self.write(tool.README_FILE, readme.replace("**not code-signed**", "**code-signed by the project**").encode())
        self.assert_fails("missing statement '**not code-signed**'")
        self.write(tool.README_FILE, (readme + "\nThe DLL is code-signed.\n").encode())
        self.assert_fails("false claim 'is code-signed'")
        self.write(tool.README_FILE, (readme + "\nThis build is production-ready.\n").encode())
        self.assert_fails("false claim 'production-ready'")
        self.write(tool.README_FILE, readme.replace("not a digital signature", "a digital signature").encode())
        self.assert_fails("not a digital signature")
        self.write(tool.README_FILE, readme.replace(SHA, OTHER_SHA).encode())
        self.assert_fails("does not state git_commit")

    # E: missing license.
    def test_a_missing_or_changed_project_license_fails(self):
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            with self.subTest(license=name):
                original = self.read(name)
                os.remove(self.path(name))
                self.assert_fails(f"missing file {name}")
                self.write(name, original.replace(b"License", b"Licence", 1))
                self.assert_fails(f"{name}: differs from the repository")
                self.write(name, original)

    # Notices.
    def test_missing_or_incomplete_notices_fail(self):
        original = self.read(tool.NOTICES_FILE)
        os.remove(self.path(tool.NOTICES_FILE))
        self.assert_fails("missing file THIRD-PARTY-NOTICES.md")
        self.write(tool.NOTICES_FILE, original.replace(b"| leaf | 2.0.0 | BSD-3-Clause |", b"| leaf | 2.0.0 |  |"))
        self.assert_fails("incomplete row")
        self.write(tool.NOTICES_FILE, original.replace(b"not legal advice", b"legal advice"))
        self.assert_fails("not-legal-advice")
        self.write(tool.NOTICES_FILE, original.replace(b"Packages: 3.", b"Packages: 4."))
        self.assert_fails("package count")

    def test_a_missing_header_or_abi_manifest_fails(self):
        for name in ("sas_pairing.h", "abi-v1-manifest.md", tool.README_FILE, tool.LIBRARY_FILE, tool.MANIFEST_FILE, tool.SUMS_FILE):
            with self.subTest(file=name):
                original = self.read(name)
                os.remove(self.path(name))
                self.assert_fails(f"missing file {name}")
                self.write(name, original)
        self.assertEqual(tool.verify(self.bundle, SHA), [])

    # F: extra binary or build garbage.
    def test_extra_binaries_and_build_files_fail(self):
        for name in ("debug.pdb", "extra.dll", "unexpected.dll", "sas_pairing_core.lib", "sas_pairing_core.exp",
                     "sas_pairing_core.ilk", "libsas_pairing_core.so", "dart-test.log", "notes.txt"):
            with self.subTest(file=name):
                self.write(name, b"x")
                self.assert_fails(f"unexpected file {name}")
                os.remove(self.path(name))
        os.makedirs(self.path("target"))
        self.assert_fails("unexpected directory target/")

    # J: the staged DLL differs from the tested build DLL.
    def test_a_staged_dll_differing_from_the_source_by_one_byte_fails(self):
        self.assertEqual(tool.verify(self.bundle, SHA, self.build), [])
        data = bytearray(self.read(tool.LIBRARY_FILE))
        data[0x10] ^= 0xFF  # an unused DOS-header byte: still a valid AMD64 DLL
        # Even with every metadata file made consistent with the changed copy:
        self.write(tool.LIBRARY_FILE, bytes(data))
        manifest = self.manifest()
        manifest["library_sha256"] = tool.sha256_file(self.path(tool.LIBRARY_FILE))
        self.write_manifest(manifest)
        self.write(tool.README_FILE, tool.readme_markdown(manifest).encode())
        self.write(tool.SUMS_FILE, tool.sums_text(self.bundle).encode())
        self.assertEqual(tool.verify(self.bundle, SHA), [])
        self.assert_fails("not byte-identical to the source library", source_library=self.build)

    def test_the_command_line_reports_failure_with_exit_status_one(self):
        # Captured, so that the expected ::error:: line does not become a CI annotation.
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
class RealWindowsDll(BundleCase):
    """The real CI artifact: an AMD64 PE32+ DLL with exactly the 25 exports."""

    def real_bytes(self):
        if not REAL_DLL or not REAL_DLL.endswith(tool.LIBRARY_FILE) or not os.path.isfile(REAL_DLL):
            self.fail(f"SAS_PAIRING_NATIVE_LIBRARY must name the built {tool.LIBRARY_FILE}: {REAL_DLL!r}")
        with open(REAL_DLL, "rb") as handle:
            return handle.read()

    def test_the_real_dll_is_amd64_with_exactly_the_25_exports(self):
        data = self.real_bytes()
        machine, characteristics, magic = tool.pe_header(data)
        self.assertEqual((machine, magic), (0x8664, 0x20B))
        self.assertTrue(characteristics & 0x2000)
        self.assertEqual(tool.check_amd64_dll(data), "AMD64 (x86_64)")
        self.assertEqual(tool.check_exports(data), 25)

    def test_the_real_dll_with_another_machine_code_is_refused(self):
        data = bytearray(self.real_bytes())
        (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
        for machine in (0x14C, 0xAA64, 0xA641):
            struct.pack_into("<H", data, pe_offset + 4, machine)
            with self.assertRaises(tool.PackagingError):
                tool.check_amd64_dll(bytes(data))

    def test_the_real_dll_stages_and_verifies(self):
        self.stage(data=self.real_bytes())
        self.assertEqual(tool.verify(self.bundle, SHA, self.build), [])
        self.assertEqual(self.manifest()["library_sha256"], tool.sha256_bytes(self.real_bytes()))


@unittest.skipUnless(shutil.which("cargo"), "cargo is not installed")
class RealDependencyGraph(unittest.TestCase):
    def test_the_locked_graph_has_license_metadata_for_every_package(self):
        metadata = tool.run_cargo_metadata(tool.RUST_TARGET)
        notices = tool.notices_markdown(metadata, tool.RUST_TARGET)
        self.assertIn("| vodozemac | 0.11.0 | Apache-2.0 | normal |", notices)
        self.assertIn("| windows-sys |", notices)
        self.assertNotIn("| sas-pairing-core |", notices)
        rows = tool.third_party_packages(metadata)
        self.assertGreater(len(rows), 10)
        self.assertTrue(all(row[2] for row in rows))


if __name__ == "__main__":
    unittest.main()
