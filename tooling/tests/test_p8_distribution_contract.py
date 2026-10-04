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


CURRENT_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "dart/README.md",
    "dart/CHANGELOG.md",
    "dart/pubspec.yaml",
    "docs/architecture.md",
    "docs/protocol-status.md",
    "docs/p8-dart-package/README.md",
    "docs/p8-dart-package/final-closure.md",
    "roadmap/README.md",
    "roadmap/P8-dart-package.md",
    "roadmap/P9-dotnet-package.md",
    "ai/context/project.md",
    "tooling/README.md",
)

# Statements that were true during P8 and are false at its closure. Historical evidence keeps its
# period-correct wording (P7 documents, the decision records, per-increment evidence sections).
STALE_PHRASES = (
    "no Dart ceremony",
    "Neither package exists yet",
    "no native API or ABI has been defined",
    "No pairing API yet",
    "distribution is not decided",
    "native binary distribution is not decided",
    "Native artifact not bundled yet",
    "The native artifact is not bundled yet",
    "P8 IN PROGRESS",
    "P8 is in progress",
    "P8 (Dart package) is in progress",
    "Dart Package IN PROGRESS",
    "P8.5 is next",
    "P8.5 next",
    "P8.6 next",
    "P8.6 is next",
    "exposes no result contents yet",
    "until the first release process is defined",
    "P9 🟡",
    "P9 (.NET PACKAGE) NEXT",
    "it does not exist yet",
)


class CurrentDocuments(unittest.TestCase):
    def test_no_stale_p8_status_in_current_documents(self):
        for relative in CURRENT_DOCUMENTS:
            text = read(os.path.join(ROOT, relative))
            if relative == "docs/p8-dart-package/README.md":
                # Per-increment evidence below "## Evidence" is historical.
                text = text.split("\n## Evidence\n", 1)[0]
            for phrase in STALE_PHRASES:
                self.assertNotIn(phrase, text, f"{relative}: stale {phrase!r}")

    def test_the_status_documents_record_p8_complete_and_p9_next(self):
        readme = read(os.path.join(ROOT, "README.md"))
        self.assertIn("P8 (Dart package) is complete", readme)
        # P9 has started since P8 closed (P9.1); P8 stays complete.
        self.assertIn("P9 (.NET package) is in progress", readme)
        self.assertIn("**.NET / C#:** in progress in P9", readme)
        for required in (
            "no qualified professional audit or formal verification is claimed",
            "This selection does not establish production security or approve production use.",
            "Do not use this project to protect production systems.",
            "neither is a security approval",
        ):
            self.assertIn(required, readme)
        roadmap = read(os.path.join(ROOT, "roadmap", "README.md"))
        self.assertIn("P8 ✅ Dart Package", roadmap)
        self.assertIn("P9 🔵 .NET Package", roadmap)
        self.assertIn("✅ **P8 COMPLETE", read(os.path.join(ROOT, "roadmap", "P8-dart-package.md")))
        self.assertIn("🔵 In progress", read(os.path.join(ROOT, "roadmap", "P9-dotnet-package.md")))
        self.assertIn("**P8 COMPLETE — DART PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION**", read(os.path.join(ROOT, "docs", "protocol-status.md")))
        changelog = read(os.path.join(ROOT, "CHANGELOG.md"))
        self.assertIn("No production release has been made", changelog)

    def test_the_final_closure_records_every_handoff_obligation_complete(self):
        closure = read(os.path.join(ROOT, "docs", "p8-dart-package", "final-closure.md"))
        self.assertIn("**P8 COMPLETE — DART PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.**", closure)
        rows = re.findall(r"(?m)^\| (\d+) \| [^\n]* \| \*\*Complete\*\* \([^)]*\) \|$", closure)
        self.assertEqual(rows, [str(number) for number in range(1, 12)])
        for increment in ("P8.1", "P8.2", "P8.2.1", "P8.3", "P8.4", "P8.5", "P8.6"):
            self.assertRegex(closure, rf"(?m)^\| {re.escape(increment)} \|")
        for decision in range(1, 7):
            self.assertIn(f"[P8-D-00{decision}](decisions.md#p8-d-00{decision}--", closure)
        package = read(os.path.join(ROOT, "docs", "p8-dart-package", "README.md"))
        handoff = package.split("## P7 wrapper handoff", 1)[1].split("\n## ", 1)[0]
        states = re.findall(r"(?m)^\| (\d+) \| [^|]+ \| (.*) \|$", handoff)
        self.assertEqual([number for number, _ in states], [str(number) for number in range(1, 12)])
        for number, state in states:
            self.assertTrue(state.startswith("**Complete.**"), number)
            for unresolved in ("planned", "later increment", "later P8", "not yet", "TODO", "deferred", "will be"):
                self.assertNotIn(unresolved, state, f"handoff row {number}")

    def test_no_document_claims_code_signing_production_approval_or_publication(self):
        claims = re.compile(
            r"code_signed[`\"']?\s*[:=]\s*[`\"']?true|\b(is|are)\s+(now\s+)?(code-)?signed\b|"
            r"\bavailable on pub\.dev\b|\bpublished (on|to) pub\.dev\b|\bis production[- ]ready\b|"
            r"\bproduction-security approved\b(?<!not production-security approved)",
            re.IGNORECASE,
        )
        for relative in CURRENT_DOCUMENTS + ("docs/p8-dart-package/decisions.md",):
            text = read(os.path.join(ROOT, relative))
            if relative == "docs/p8-dart-package/README.md":
                # The evidence section records the mutations, which quote the false claims.
                text = text.split("\n## Evidence\n", 1)[0]
            for line in text.splitlines():
                for match in claims.finditer(line):
                    before = line[max(0, match.start() - 40) : match.start()].lower()
                    if re.search(r"\b(not|no|never|nor|neither|without)\b[^.]*$", before):
                        continue  # a negated statement
                    self.fail(f"{relative}: claim {match.group(0)!r} in: {line[:160]}")


if __name__ == "__main__":
    unittest.main()
