"""P8-D-006 distribution contract guards: CI workflows, package metadata, and license copies.

The Windows Dart job is the only place a distribution artifact is uploaded: exactly one
upload-artifact step in all workflows, Windows-only and push-only, after staging, every Dart
test against the staged DLL, the native freeze test, and re-verification. No workflow creates a
tag, GitHub Release, or pub.dev publication. The Dart package stays unpublished at
0.1.0-dev.1 with unmodified license copies. Standard library only (no YAML parser): the checks
read the workflow text by step.
"""

import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")
DART_WORKFLOW = os.path.join(WORKFLOWS, "dart-package.yml")
ARTIFACT_NAME = "sas-pairing-dart-windows-x64-abi1-${{ github.sha }}"
BUNDLE_DIR = "dist/sas-pairing-dart-windows-x64-abi1"


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def workflow_files():
    return sorted(
        os.path.join(WORKFLOWS, name)
        for name in os.listdir(WORKFLOWS)
        if name.endswith((".yml", ".yaml"))
    )


def steps(text):
    """The step blocks of every job: each starts at a `      - ` line under `steps:`."""
    blocks, current, in_steps = [], None, False
    for line in text.splitlines():
        if re.match(r"^    steps:\s*$", line):
            in_steps = True
            continue
        if in_steps and re.match(r"^  \S", line):  # the next job
            in_steps = False
        if not in_steps:
            continue
        if line.startswith("      - "):
            current = [line]
            blocks.append(current)
        elif current is not None and (line.startswith("        ") or not line.strip()):
            current.append(line)
        elif line.strip().startswith("#"):
            continue
    return ["\n".join(block) for block in blocks]


def step_name(block):
    match = re.search(r"^\s*-?\s*name:\s*(.+)$", block, re.MULTILINE)
    return match.group(1).strip() if match else ""


def step_if(block):
    match = re.search(r"^\s*-?\s*if:\s*(.+)$", block, re.MULTILINE)
    return match.group(1).strip() if match else ""


class Workflows(unittest.TestCase):
    def setUp(self):
        self.dart = read(DART_WORKFLOW)
        self.dart_steps = steps(self.dart)
        self.assertGreater(len(self.dart_steps), 20)

    def uploads(self):
        found = []
        for path in workflow_files():
            for block in steps(read(path)):
                if "upload-artifact" in block:
                    found.append((os.path.basename(path), block))
        return found

    def index(self, name):
        names = [step_name(block) for block in self.dart_steps]
        self.assertIn(name, names)
        return names.index(name)

    def test_exactly_one_upload_and_it_is_the_windows_bundle_of_the_exact_commit(self):
        uploads = self.uploads()
        self.assertEqual([path for path, _ in uploads], ["dart-package.yml"], uploads)
        block = uploads[0][1]
        self.assertIn("uses: actions/upload-artifact@v7", block)
        condition = step_if(block)
        self.assertIn("runner.os == 'Windows'", condition)
        self.assertIn("github.event_name == 'push'", condition)
        self.assertNotIn("||", condition)
        self.assertRegex(block, r"(?m)^\s+name: " + re.escape(ARTIFACT_NAME) + r"$")
        self.assertRegex(block, r"(?m)^\s+path: " + re.escape(BUNDLE_DIR) + r"/?$")
        self.assertRegex(block, r"(?m)^\s+if-no-files-found: error$")
        self.assertRegex(block, r"(?m)^\s+retention-days: 90$")
        for forbidden in (".so", "libsas_pairing_core", "target/release", "latest", "overwrite: true"):
            self.assertNotIn(forbidden, block)

    def test_no_linux_or_shared_object_distribution(self):
        for path, block in self.uploads():
            self.assertNotIn("Linux", step_if(block), path)
            self.assertNotIn("ubuntu", block, path)
        # The Linux matrix entry tests its job-local build output, never a staged bundle.
        linux = re.search(r"- os: ubuntu-latest\n((?:            .*\n)+)", self.dart)
        self.assertIsNotNone(linux)
        self.assertIn("tested_library: core/target/release/libsas_pairing_core.so", linux.group(1))
        self.assertNotIn("dist/", linux.group(1))
        for block in self.dart_steps:
            if "package_dart_native.py" in block:
                self.assertIn("runner.os == 'Windows'", step_if(block), step_name(block))

    def test_every_windows_dart_test_loads_the_staged_dll(self):
        windows = re.search(r"- os: windows-latest\n((?:            .*\n)+)", self.dart)
        self.assertIsNotNone(windows)
        self.assertIn(f"tested_library: {BUNDLE_DIR}/sas_pairing_core.dll", windows.group(1))
        self.assertIn(
            "SAS_PAIRING_NATIVE_LIBRARY: ${{ github.workspace }}/${{ matrix.tested_library }}",
            self.dart,
        )
        self.assertEqual(self.dart.count("SAS_PAIRING_NATIVE_LIBRARY:"), 1)
        stage = self.index("Stage the Windows x64 distribution bundle")
        verify = self.index("Verify the staged bundle (hash identity, PE machine, exports)")
        upload = self.index("Upload the tested Windows x64 bundle (experimental CI artifact)")
        build = self.index("Build the native ABI v1 artifact")
        audit = self.index("Native ABI export audit")
        self.assertLess(build, audit)
        self.assertLess(audit, stage)
        self.assertLess(stage, verify)
        dart_tests = [
            i for i, block in enumerate(self.dart_steps) if re.search(r"^\s+dart test\b", block, re.MULTILINE)
        ]
        self.assertGreaterEqual(len(dart_tests), 7)
        self.assertLess(verify, min(dart_tests))
        for name in (
            "Real native ABI v1 smoke (symbols and version)",
            "Real native lifecycle (${{ matrix.lifecycle }})",
            "Real native network (Windows)",
            "Real native ceremony (Windows)",
            "Native ABI v1 freeze consistency",
            "Re-verify the tested bundle before upload",
            "Packaging tool tests (real staged DLL)",
        ):
            self.assertLess(stage, self.index(name), name)
            self.assertLess(self.index(name), upload, name)
        reverify = self.dart_steps[self.index("Re-verify the tested bundle before upload")]
        self.assertGreater(self.index("Re-verify the tested bundle before upload"), max(dart_tests))
        self.assertIn('--source-library "$BUILD_LIBRARY"', reverify)
        self.assertIn('--git-sha "$GITHUB_SHA"', reverify)
        self.assertEqual(upload, len(self.dart_steps) - 2)

    def test_staging_takes_the_rust_target_from_the_toolchain_and_the_commit_from_github(self):
        block = self.dart_steps[self.index("Stage the Windows x64 distribution bundle")]
        self.assertIn("rustc -vV", block)
        self.assertIn('--rust-target "$target"', block)
        self.assertIn('--git-sha "$GITHUB_SHA"', block)
        self.assertIn('--library "$BUILD_LIBRARY"', block)
        self.assertIn(f"--output {BUNDLE_DIR}", block)

    def test_no_release_tag_or_publication_automation(self):
        forbidden = {
            "a release action": re.compile(
                r"action-gh-release|actions/create-release|upload-release-asset|release-action|"
                r"release-drafter|semantic-release|goreleaser",
                re.IGNORECASE,
            ),
            "a gh release command": re.compile(r"\bgh\s+release\b"),
            "a tag": re.compile(r"\bgit\s+tag\b|\bgit\s+push\b[^\n]*--tags|\bcreate-tag\b|git/refs/tags"),
            "a pub.dev publication": re.compile(r"\bpub\s+publish\b|\bpub\.dev\b|setup-dart[^\n]*publish|PUB_CREDENTIALS"),
            "write permissions": re.compile(r"contents:\s*write|packages:\s*write|id-token:\s*write"),
            "a release or tag trigger": re.compile(r"(?m)^\s+(release|tags|tags-ignore):"),
        }
        for path in workflow_files():
            # Comments may name what is forbidden; only workflow content counts.
            lines = read(path).splitlines()
            text = "\n".join(line for line in lines if not line.strip().startswith("#"))
            for what, pattern in forbidden.items():
                self.assertIsNone(pattern.search(text), f"{os.path.basename(path)}: {what}")
        self.assertRegex(self.dart, r"(?m)^permissions:\n  contents: read$")


class PackageMetadata(unittest.TestCase):
    def test_the_package_is_unpublished_and_pre_alpha(self):
        pubspec = read(os.path.join(ROOT, "dart", "pubspec.yaml"))
        self.assertRegex(pubspec, r"(?m)^publish_to: none$")
        self.assertRegex(pubspec, r"(?m)^version: 0\.1\.0-dev\.1$")
        for stale in ("No pairing API yet", "not decided", "in progress"):
            self.assertNotIn(stale, pubspec)

    def test_the_package_license_files_are_unmodified_copies(self):
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            with open(os.path.join(ROOT, name), "rb") as root, open(os.path.join(ROOT, "dart", name), "rb") as copy:
                self.assertEqual(copy.read(), root.read(), name)

    def test_the_package_changelog_has_the_pre_alpha_entry(self):
        changelog = read(os.path.join(ROOT, "dart", "CHANGELOG.md"))
        self.assertIn("\n## 0.1.0-dev.1\n", changelog)
        self.assertIn("sas-pairing-dart-windows-x64-abi1-<commit>", changelog)

    def test_no_native_binary_is_committed_anywhere_in_the_package(self):
        for directory, _subdirectories, files in os.walk(os.path.join(ROOT, "dart")):
            if ".dart_tool" in directory:
                continue
            for name in files:
                self.assertFalse(name.lower().endswith((".dll", ".so", ".dylib", ".pdb", ".lib")), name)


if __name__ == "__main__":
    unittest.main()
