"""P9-D-006 distribution contract guards: the .NET CI workflow, the package metadata, and the consumer smoke.

The Windows .NET job uploads exactly two distribution artifacts, Windows-only and push-only, after
staging the native bundle, running every .NET test (Release) against the staged DLL, packing the
tested build, staging and verifying the managed bundle, the local-feed consumer smoke, the
packaging tool tests, the native freeze test, and re-verification. Nothing is pushed to nuget.org
or any feed, and no tag or GitHub Release is created. Standard library only (no YAML parser): the
checks read the workflow text by step.
"""

import os
import re
import unittest
import xml.etree.ElementTree as ElementTree

from test_p8_distribution_contract import ROOT, WORKFLOWS, read, step_if, step_name, steps, workflow_files

DOTNET_WORKFLOW = os.path.join(WORKFLOWS, "dotnet-package.yml")
NUGET_BUNDLE = "dist/sas-pairing-dotnet-nuget"
NATIVE_BUNDLE = "dist/sas-pairing-dotnet-windows-x64-abi1"
NUGET_ARTIFACT = "sas-pairing-dotnet-nuget-${{ github.sha }}"
NATIVE_ARTIFACT = "sas-pairing-dotnet-windows-x64-abi1-${{ github.sha }}"
WINDOWS_PUSH = "runner.os == 'Windows' && github.event_name == 'push'"


def workflow_text(path):
    """The workflow without comment lines: comments may name what is forbidden."""
    return "\n".join(line for line in read(path).splitlines() if not line.strip().startswith("#"))


class DotnetWorkflow(unittest.TestCase):
    def setUp(self):
        self.text = read(DOTNET_WORKFLOW)
        self.steps = steps(self.text)
        self.names = [step_name(block) for block in self.steps]
        self.assertGreater(len(self.steps), 20)

    def index(self, name):
        self.assertIn(name, self.names)
        return self.names.index(name)

    def block(self, name):
        return self.steps[self.index(name)]

    def test_exactly_two_uploads_the_managed_and_the_native_bundle_of_the_exact_commit(self):
        uploads = [block for block in self.steps if "upload-artifact" in block]
        self.assertEqual(len(uploads), 2)
        expected = ((NUGET_ARTIFACT, NUGET_BUNDLE), (NATIVE_ARTIFACT, NATIVE_BUNDLE))
        for block, (name, path) in zip(uploads, expected):
            self.assertIn("uses: actions/upload-artifact@v7", block)
            self.assertEqual(step_if(block), WINDOWS_PUSH)
            self.assertRegex(block, r"(?m)^\s+name: " + re.escape(name) + r"$")
            self.assertRegex(block, r"(?m)^\s+path: " + re.escape(path) + r"/?$")
            self.assertRegex(block, r"(?m)^\s+if-no-files-found: error$")
            self.assertRegex(block, r"(?m)^\s+retention-days: 90$")
            for forbidden in (".so", "libsas_pairing_core", "target/release", "latest", "current", "overwrite: true", "ubuntu"):
                self.assertNotIn(forbidden, block)

    def test_no_linux_distribution(self):
        linux = re.search(r"- os: ubuntu-latest\n((?:            .*\n)+)", self.text)
        self.assertIsNotNone(linux)
        self.assertIn("tested_library: core/target/release/libsas_pairing_core.so", linux.group(1))
        self.assertNotIn("dist/", linux.group(1))
        for block in self.steps:
            if re.search(r"package_dotnet_(native|nuget)\.py|dotnet pack|upload-artifact|PackageSmoke", block):
                self.assertIn("runner.os == 'Windows'", step_if(block), step_name(block))

    def test_every_dotnet_test_runs_in_release_against_the_staged_dll(self):
        windows = re.search(r"- os: windows-latest\n((?:            .*\n)+)", self.text)
        self.assertIn(f"tested_library: {NATIVE_BUNDLE}/sas_pairing_core.dll", windows.group(1))
        self.assertEqual(self.text.count("SAS_PAIRING_NATIVE_LIBRARY:"), 1)
        self.assertIn("SAS_PAIRING_NATIVE_LIBRARY: ${{ github.workspace }}/${{ matrix.tested_library }}", self.text)
        tests = [i for i, block in enumerate(self.steps) if re.search(r"\bdotnet test\b", block)]
        self.assertEqual(len(tests), 6)
        for i in tests:
            self.assertIn("dotnet test -c Release --no-build", self.steps[i])
        self.assertIn("dotnet build -c Release --no-restore -warnaserror", self.block("dotnet build"))
        stage = self.index("Stage the Windows x64 native bundle")
        verify = self.index("Verify the staged native bundle (hash identity, PE machine, exports)")
        self.assertLess(self.index("Native ABI export audit"), stage)
        self.assertLess(stage, verify)
        self.assertLess(verify, min(tests))
        self.assertIn('--source-library "$BUILD_LIBRARY"', self.steps[verify])

    def test_the_tested_release_build_is_packed_with_the_exact_commit_and_verified(self):
        pack = self.block("Pack the managed package (tested Release build)")
        self.assertIn("dotnet pack src/SasPairing/SasPairing.csproj -c Release --no-build --no-restore", pack)
        self.assertIn('-p:RepositoryCommit="$GITHUB_SHA"', pack)
        self.assertNotRegex(pack, r"IncludeSymbols|SymbolPackageFormat|snupkg|--version-suffix|-p:Version")
        stage = self.block("Stage and verify the managed NuGet bundle (assembly identity)")
        self.assertIn('--git-sha "$GITHUB_SHA"', stage)
        self.assertIn("--assembly dotnet/src/SasPairing/bin/Release/net10.0/SasPairing.dll", stage)
        self.assertIn("--assembly dotnet/tests/SasPairing.Tests/bin/Release/net10.0/SasPairing.dll", stage)
        self.assertIn(f"--output {NUGET_BUNDLE}", stage)
        tests = [i for i, block in enumerate(self.steps) if re.search(r"\bdotnet test\b", block)]
        self.assertGreater(self.index("Pack the managed package (tested Release build)"), max(tests))

    def test_the_consumer_smoke_restores_the_staged_package_and_runs_the_staged_dll(self):
        smoke = self.block("Local NuGet consumer smoke (packed assembly + staged DLL)")
        self.assertIn("working-directory: dotnet/tests/SasPairing.PackageSmoke", smoke)
        self.assertIn("if grep -F 'ProjectReference' SasPairing.PackageSmoke.csproj; then exit 1; fi", smoke)
        self.assertIn("rm -rf bin obj", smoke)
        self.assertIn('dotnet run -c Release --no-build -- "$SAS_PAIRING_NATIVE_LIBRARY"', smoke)
        self.assertIn('test "$built" = "$restored"', smoke)
        self.assertIn('test "$built" = "$loaded"', smoke)
        self.assertLess(self.index("Stage and verify the managed NuGet bundle (assembly identity)"),
                        self.index("Local NuGet consumer smoke (packed assembly + staged DLL)"))

    def test_both_bundles_are_reverified_after_every_test_and_before_upload(self):
        reverify = self.index("Re-verify both tested bundles before upload")
        block = self.steps[reverify]
        self.assertIn("package_dotnet_native.py verify", block)
        self.assertIn('--source-library "$BUILD_LIBRARY"', block)
        self.assertIn("package_dotnet_nuget.py verify", block)
        self.assertIn("--assembly dotnet/tests/SasPairing.Tests/bin/Release/net10.0/SasPairing.dll", block)
        uploads = [i for i, b in enumerate(self.steps) if "upload-artifact" in b]
        for name in ("dotnet test", "Real native ABI v1 smoke (exports and version)", "Real native lifecycle (public API)",
                     "Real native network (public API)", "Real native ceremony (public API)", "Real native result (public API)",
                     "Local NuGet consumer smoke (packed assembly + staged DLL)",
                     "Packaging tool tests (real staged DLL and package)", "Native ABI v1 freeze consistency"):
            self.assertLess(self.index(name), reverify, name)
        self.assertLess(reverify, min(uploads))
        self.assertEqual(max(uploads), len(self.steps) - 2)
        self.assertEqual(step_if(self.steps[-1]), WINDOWS_PUSH)

    def test_the_closure_documents_trigger_the_workflow(self):
        for path in ("'dotnet/**'", "'docs/p9-dotnet-package/**'", "'roadmap/P9-dotnet-package.md'",
                     "'tooling/package_dotnet_native.py'", "'tooling/package_dotnet_nuget.py'", "'tooling/tests/**'"):
            self.assertEqual(self.text.count(f"      - {path}\n"), 2, path)

    def test_no_feed_publication_release_or_tag_anywhere(self):
        forbidden = {
            "a NuGet push": re.compile(r"(?i)\bnuget\s+push\b|\bnuget\.exe\b|NUGET_API_KEY|NUGET_AUTH_TOKEN|api\.nuget\.org|nuget\.pkg\.github\.com"),
            "a package publish action": re.compile(r"(?i)publish-nuget|nuget/setup-nuget|actions/setup-nuget|gpr\s+push|packages:\s*write"),
            "a release": re.compile(r"(?i)action-gh-release|actions/create-release|upload-release-asset|\bgh\s+release\b|release-drafter|semantic-release"),
            "a tag": re.compile(r"\bgit\s+tag\b|\bgit\s+push\b[^\n]*--tags|\bcreate-tag\b|git/refs/tags"),
            "write permissions": re.compile(r"contents:\s*write|id-token:\s*write"),
            "a release or tag trigger": re.compile(r"(?m)^\s+(release|tags|tags-ignore):"),
        }
        for path in workflow_files():
            text = workflow_text(path)
            for what, pattern in forbidden.items():
                self.assertIsNone(pattern.search(text), f"{os.path.basename(path)}: {what}")
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read$")

    def test_the_packaging_tool_tests_require_the_real_dll_and_package(self):
        block = self.block("Packaging tool tests (real staged DLL and package)")
        self.assertIn("SAS_PAIRING_REQUIRE_REAL_DLL: '1'", block)
        self.assertIn("SAS_PAIRING_REQUIRE_REAL_NUPKG: '1'", block)
        self.assertIn("if grep -E 'Real(WindowsDll|Nupkg).* skipped' packaging-tests.log; then exit 1; fi", block)


def xml(*parts):
    return ElementTree.parse(os.path.join(ROOT, *parts)).getroot()


class PackageMetadata(unittest.TestCase):
    def test_the_library_is_packable_at_the_pre_release_version_with_no_dependency(self):
        project = xml("dotnet", "src", "SasPairing", "SasPairing.csproj")
        values = {element.tag: (element.text or "").strip() for element in project.iter()}
        self.assertEqual(values["IsPackable"], "true")
        self.assertEqual(values["PackageId"], "SasPairing")
        self.assertEqual((values["VersionPrefix"], values["VersionSuffix"]), ("0.1.0", "dev.1"))
        self.assertEqual(values["PackageLicenseExpression"], "MIT OR Apache-2.0")
        self.assertEqual(values["PackageReadmeFile"], "README.md")
        self.assertEqual(values["RepositoryUrl"], "https://github.com/Soneka96/sas-pairing")
        for absent in ("PackageReference", "RepositoryCommit", "TargetFrameworks", "RuntimeIdentifier", "IncludeSymbols", "Version"):
            self.assertNotIn(absent, values)
        props = xml("dotnet", "Directory.Build.props")
        self.assertEqual([e.text for e in props.iter("TargetFramework")], ["net10.0"])
        self.assertEqual(list(props.iter("TargetFrameworks")), [])

    def test_no_test_project_is_packable(self):
        for project in ("SasPairing.Tests", "SasPairing.PackageSmoke"):
            root = xml("dotnet", "tests", project, f"{project}.csproj")
            self.assertEqual([e.text for e in root.iter("IsPackable")], ["false"], project)

    def test_the_consumer_smoke_references_the_package_never_the_project(self):
        root = xml("dotnet", "tests", "SasPairing.PackageSmoke", "SasPairing.PackageSmoke.csproj")
        self.assertEqual(list(root.iter("ProjectReference")), [])
        references = [(e.get("Include"), e.get("Version")) for e in root.iter("PackageReference")]
        self.assertEqual(references, [("SasPairing", "0.1.0-dev.1")])
        config = xml("dotnet", "tests", "SasPairing.PackageSmoke", "nuget.config")
        sources = config.find("packageSources")
        self.assertEqual(sources[0].tag, "clear")
        self.assertEqual([(e.get("key"), e.get("value")) for e in sources.iter("add")],
                         [("sas-pairing-dotnet-nuget", "../../../dist/sas-pairing-dotnet-nuget")])
        self.assertNotIn("PackageSmoke", read(os.path.join(ROOT, "dotnet", "SasPairing.sln")))

    def test_no_native_binary_or_package_is_committed_under_dotnet(self):
        for directory, _subdirectories, files in os.walk(os.path.join(ROOT, "dotnet")):
            if re.search(r"[\\/](bin|obj|TestResults)([\\/]|$)", directory):
                continue
            for name in files:
                self.assertFalse(name.lower().endswith((".dll", ".so", ".dylib", ".pdb", ".nupkg", ".snupkg")), name)


CURRENT_DOCUMENTS = (
    "README.md",
    "CHANGELOG.md",
    "dotnet/README.md",
    "dotnet/CHANGELOG.md",
    "dotnet/src/SasPairing/SasPairing.csproj",
    "docs/architecture.md",
    "docs/protocol-status.md",
    "docs/p9-dotnet-package/README.md",
    "docs/p9-dotnet-package/final-closure.md",
    "roadmap/README.md",
    "roadmap/P9-dotnet-package.md",
    "roadmap/P10-consumer-integration.md",
    "ai/context/project.md",
    "tooling/README.md",
)

# Statements that were true during P9 and are false at its closure. Historical evidence keeps its
# period-correct wording (the decision records and the per-increment evidence sections).
STALE_PHRASES = (
    "P9 IN PROGRESS",
    "P9 is in progress",
    "P9 (.NET package) is in progress",
    "P9 (.NET PACKAGE) IN PROGRESS",
    ".NET Package is in progress",
    "in progress in P9",
    "P9.5 next",
    "P9.6 next",
    "P9.6 is next",
    "P9.6 NEXT",
    "is next and not started. Its native",
    "Next: P9.6",
    "Current state (P9.5)",
    "Package layout (P9.5)",
    "No NuGet package exists",
    "no NuGet package exists",
    "project is not packable",
    "IsPackable false",
    "not packable or published",
    "not packed or published",
    "P9.6 decides distribution",
    "distribution is not decided",
    "distribution undecided",
    "planned idiomatic .NET wrapper",
    "will provide an idiomatic C#",
    "no public pairing API exists yet",
    "P9, the .NET package, is next",
    "P9 is next",
    "P9 🔵",
    "P10 🟡",
    "Planned; gated on usable",
)


def current_text(relative):
    text = read(os.path.join(ROOT, relative))
    if relative == "docs/p9-dotnet-package/README.md":
        # Per-increment evidence below "## Evidence" is historical.
        text = text.split("\n## Evidence\n", 1)[0]
    return text


class CurrentDocuments(unittest.TestCase):
    def test_no_stale_p9_status_in_current_documents(self):
        for relative in CURRENT_DOCUMENTS:
            text = current_text(relative)
            for phrase in STALE_PHRASES:
                self.assertNotIn(phrase, text, f"{relative}: stale {phrase!r}")

    def test_the_status_documents_record_p9_complete_and_p10_next(self):
        readme = read(os.path.join(ROOT, "README.md"))
        self.assertIn("P9 experimental .NET package complete", readme)
        self.assertIn("P9 (.NET package) is complete", readme)
        # P10 has started since P9 closed (P10.1 complete, P10-D-001); P9 stays complete.
        self.assertIn("P10 (consumer integration / DovahLink example) is in progress", readme)
        self.assertIn("**.NET / C#:** implemented experimentally in P9", readme)
        for required in (
            "no qualified professional audit or formal verification is claimed",
            "This selection does not establish production security or approve production use.",
            "Do not use this project to protect production systems.",
            "not published to nuget.org",
        ):
            self.assertIn(required, readme)
        roadmap = read(os.path.join(ROOT, "roadmap", "README.md"))
        self.assertIn("P9 ✅ .NET Package", roadmap)
        self.assertIn("P10 🔵 Consumer Integration / DovahLink Example", roadmap)
        self.assertIn("✅ **P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.**", read(os.path.join(ROOT, "roadmap", "P9-dotnet-package.md")))
        self.assertIn("🔵 **In progress — P10.1 complete.**", read(os.path.join(ROOT, "roadmap", "P10-consumer-integration.md")))
        status = read(os.path.join(ROOT, "docs", "protocol-status.md"))
        self.assertIn("**P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION**", status)
        self.assertIn("**P10 (consumer integration / DovahLink example) is in progress**", status)
        self.assertIn("**Status: P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.**", current_text("docs/p9-dotnet-package/README.md"))
        self.assertIn("## Current state (P9 complete)", read(os.path.join(ROOT, "dotnet", "README.md")))
        self.assertIn("P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION", read(os.path.join(ROOT, "ai", "context", "project.md")))
        self.assertIn("No production release has been made", read(os.path.join(ROOT, "CHANGELOG.md")))
        changelog = read(os.path.join(ROOT, "dotnet", "CHANGELOG.md"))
        self.assertIn("\n## 0.1.0-dev.1\n", changelog)
        for name in ("sas-pairing-dotnet-nuget-<commit>", "sas-pairing-dotnet-windows-x64-abi1-<commit>", "Not published to nuget.org"):
            self.assertIn(name, changelog)

    def test_the_package_readme_gives_the_exact_distribution_instructions(self):
        readme = read(os.path.join(ROOT, "dotnet", "README.md"))
        for required in (
            "## Installation (experimental CI artifacts)",
            "**Nothing is published to nuget.org**",
            "`sas-pairing-dotnet-nuget-<commit>`",
            "`sas-pairing-dotnet-windows-x64-abi1-<commit>`",
            "**no native library**",
            "**same exact commit**",
            "**absolute path**",
            "`SasPairingRuntime.Create(nativeLibraryPath)`",
            "not a signature",
            "requires an OS process restart",
            "Windows x64 is the only pairing distribution target",
        ):
            self.assertIn(required, readme)

    def test_the_final_closure_records_every_handoff_obligation_complete(self):
        closure = read(os.path.join(ROOT, "docs", "p9-dotnet-package", "final-closure.md"))
        self.assertIn("**P9 COMPLETE — .NET PACKAGE + WINDOWS X64 NATIVE DISTRIBUTION.**", closure)
        rows = re.findall(r"(?m)^\| (\d+) \| [^\n]* \| \*\*Complete\*\* \([^)]*\) \|$", closure)
        self.assertEqual(rows, [str(number) for number in range(1, 12)])
        for increment in ("P9.1", "P9.2", "P9.3", "P9.4", "P9.5", "P9.6"):
            self.assertRegex(closure, rf"(?m)^\| {re.escape(increment)} \|")
        for decision in range(1, 7):
            self.assertIn(f"[P9-D-00{decision}](decisions.md#p9-d-00{decision}--", closure)
        for required in ("03afc8dd6ef8c473ef648ec7e06cee5042d0083a", "24cb89d3ecbfe00616118b5ae996c38dd849ec55",
                         "**P10 — Consumer Integration / DovahLink Example**", "**Unsigned.**", "**same exact commit**"):
            self.assertIn(required, closure)
        package = read(os.path.join(ROOT, "docs", "p9-dotnet-package", "README.md"))
        handoff = package.split("## P7 wrapper handoff", 1)[1].split("\n## ", 1)[0]
        states = re.findall(r"(?m)^\| (\d+) \| [^|]+ \| (.*) \|$", handoff)
        self.assertEqual([number for number, _ in states], [str(number) for number in range(1, 12)])
        for number, state in states:
            self.assertTrue(state.startswith("**Complete.**"), number)
            for unresolved in ("planned", "later increment", "later P9", "not yet", "TODO", "deferred", "will be", "until P9"):
                self.assertNotIn(unresolved, state, f"handoff row {number}")

    def test_no_document_claims_signing_production_approval_or_feed_publication(self):
        claims = re.compile(
            r"code_signed[`\"']?\s*[:=]\s*[`\"']?true|published_to_nuget[`\"']?\s*[:=]\s*[`\"']?true|"
            r"\b(is|are)\s+(now\s+)?(code-)?signed\b|\bavailable on nuget\.org\b|\bpublished (on|to) nuget\.org\b|"
            r"\bis production[- ]ready\b|\bproduction-security approved\b",
            re.IGNORECASE,
        )
        for relative in CURRENT_DOCUMENTS + ("docs/p9-dotnet-package/decisions.md",):
            for line in current_text(relative).splitlines():
                for match in claims.finditer(line):
                    before = line[max(0, match.start() - 40) : match.start()].lower()
                    if re.search(r"\b(not|no|never|nor|neither|without|nothing)\b[^.]*$", before):
                        continue  # a negated statement
                    self.fail(f"{relative}: claim {match.group(0)!r} in: {line[:160]}")


if __name__ == "__main__":
    unittest.main()
