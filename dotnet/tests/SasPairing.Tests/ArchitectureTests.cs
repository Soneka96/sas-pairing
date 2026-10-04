using System.Reflection;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9.1 architecture and scope guards over the production sources (comments removed) and the built assembly:
/// raw interop private and localized under <c>Interop/</c>, one explicit-path load and no release of the
/// image, no library search, no public surface, and nothing of later increments, the protocol, cryptography,
/// networking, or threads.
/// </summary>
public sealed partial class ArchitectureTests
{
    private static readonly Assembly Library = typeof(AbiV1Constants).Assembly;

    private static void AssertAbsent(Regex pattern, string what)
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            Match match = pattern.Match(code);
            Assert.False(match.Success, $"{file}: {what}: \"{(match.Success ? match.Value : "")}\"");
        }
    }

    [Fact]
    public void TheAssemblyExportsNoPublicType()
    {
        // P9.1 has no public API: the allowlist is empty (P9.2 starts the public surface).
        string[] allowed = [];
        Assert.Equal(allowed, Library.GetExportedTypes().Select(t => t.FullName));
        Assert.DoesNotContain(Library.GetTypes(), t => t.IsPublic);
    }

    [Fact]
    public void NoRawInteropConceptIsVisibleOutsideTheAssembly()
    {
        string[] forbidden = ["NativeAbi", "NativeLibraryLoader", "NativeAbiV1Loader", "NativeBindings", "FunctionTable", "NativeEvent", "nativeHandle", "Handle", "Pointer", "sas_pairing_", "AbiV1", "Interop"];
        foreach (Type type in Library.GetExportedTypes())
        {
            foreach (string name in forbidden)
            {
                Assert.DoesNotContain(name, type.FullName!, StringComparison.OrdinalIgnoreCase);
            }

            foreach (MemberInfo member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                Assert.False(member is FieldInfo { FieldType.IsFunctionPointer: true }, $"{type}.{member.Name}");
                Assert.False(member is FieldInfo { FieldType.IsPointer: true }, $"{type}.{member.Name}");
            }
        }
    }

    [Fact]
    public void InternalsAreVisibleOnlyToTheTestAssembly()
    {
        string[] friends = [.. Library.GetCustomAttributes<System.Runtime.CompilerServices.InternalsVisibleToAttribute>().Select(a => a.AssemblyName)];
        Assert.Equal(["SasPairing.Tests"], friends);
    }

    [Fact]
    public void NoProductionTypeIsDeclaredPublic()
    {
        AssertAbsent(PublicTypeDeclaration(), "a public type declaration");
    }

    [Fact]
    public void P91SourceLivesOnlyUnderInterop()
    {
        IReadOnlyList<string> files = ProductionSource.Files();
        Assert.NotEmpty(files);
        Assert.All(files, file => Assert.StartsWith("Interop/", file, StringComparison.Ordinal));
        string[] directories = [.. Directory.EnumerateDirectories(ProductionSource.Directory).Select(Path.GetFileName).Where(d => d is not ("bin" or "obj"))!];
        Assert.Equal(["Interop"], directories);
    }

    [Fact]
    public void UnsafeCodeIsLocalizedUnderInteropAndEveryUnsafeDeclarationIsJustified()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            if (!file.StartsWith("Interop/", StringComparison.Ordinal))
            {
                Assert.DoesNotMatch(UnsafeConstruct(), code);
            }
        }

        int unsafeDeclarations = 0;
        foreach (string file in ProductionSource.Files())
        {
            string[] code = ProductionSource.Code(file).Split('\n');
            string[] raw = ProductionSource.Raw(file).Split('\n');
            Assert.Equal(raw.Length, code.Length);
            for (int line = 0; line < code.Length; line++)
            {
                if (!UnsafeKeyword().IsMatch(code[line]))
                {
                    continue;
                }

                unsafeDeclarations++;
                int previous = line - 1;
                while (previous >= 0 && raw[previous].TrimStart().StartsWith('['))
                {
                    previous--;
                }

                Assert.True(previous >= 0 && raw[previous].TrimStart().StartsWith("// UNSAFE: ", StringComparison.Ordinal), $"{file}:{line + 1}: unsafe without a preceding `// UNSAFE:` justification");
            }
        }

        Assert.True(unsafeDeclarations > 0);
    }

    [Fact]
    public void TheOnlyNativeLibraryLoadIsTheExplicitCanonicalPathInTheLoader()
    {
        List<(string File, string Match)> loads = [];
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            loads.AddRange(NativeLibraryLoadCall().Matches(code).Select(m => (file, m.Value)));
        }

        Assert.Equal([("Interop/NativeLibraryLoader.cs", "NativeLibrary.Load(path)")], loads);
        AssertAbsent(NativeLibraryAnyLoad(), "a NativeLibrary load other than Load(path)");
    }

    [Fact]
    public void ProductionNeverReleasesTheNativeImage()
    {
        AssertAbsent(NativeLibraryFree(), "NativeLibrary.Free");
        AssertAbsent(FinalizerOrRelease(), "a finalizer, SafeHandle, disposal, or shutdown release");
    }

    [Fact]
    public void ProductionUsesNoDefaultLibraryResolution()
    {
        AssertAbsent(DefaultResolution(), "default DllImport / LibraryImport / resolver binding");
        AssertAbsent(LibrarySearch(), "a library search location, basename, or download");
    }

    [Fact]
    public void ProductionImplementsNoCryptographyProtocolNetworkingOrThreads()
    {
        AssertAbsent(Cryptography(), "cryptography");
        AssertAbsent(ProtocolCode(), "protocol framing, parsing, encoding, or timing");
        AssertAbsent(Networking(), "networking");
        AssertAbsent(Threading(), "a thread, task, timer, or asynchronous worker");
    }

    [Fact]
    public void ProductionDeclaresNoHighLevelWrapper()
    {
        AssertAbsent(HighLevelWrapper(), "a high-level lifecycle, network, ceremony, or result wrapper");
        string[] types = [.. Library.GetTypes().Where(t => !t.Name.StartsWith('<')).Select(t => t.Name)];
        foreach (string name in types)
        {
            Assert.DoesNotMatch(HighLevelTypeName(), name);
        }
    }

    [Fact]
    public void TheDetectorsMatchWhatTheyForbid()
    {
        Assert.Matches(NativeLibraryFree(), "NativeLibrary.Free(handle);");
        Assert.Matches(NativeLibraryAnyLoad(), "NativeLibrary.Load(\"sas_pairing_core\")");
        Assert.Matches(NativeLibraryAnyLoad(), "NativeLibrary.TryLoad(path, out _)");
        Assert.DoesNotMatch(NativeLibraryAnyLoad(), "NativeLibrary.Load(path)");
        Assert.Matches(DefaultResolution(), "[DllImport(\"sas_pairing_core\")]");
        Assert.Matches(DefaultResolution(), "[LibraryImport(\"sas_pairing_core\")]");
        Assert.Matches(DefaultResolution(), "static extern int sas_pairing_runtime_create(ulong* x);");
        Assert.Matches(LibrarySearch(), "Path.Combine(AppContext.BaseDirectory, \"x\")");
        Assert.Matches(PublicTypeDeclaration(), "public sealed unsafe class AbiV1FunctionTable");
        Assert.Matches(FinalizerOrRelease(), "~Loader() { }");
        Assert.Matches(Networking(), "new TcpListener(address, 0)");
        Assert.Matches(Threading(), "new Timer(callback)");
        Assert.Matches(Cryptography(), "using System.Security.Cryptography;");
        Assert.Matches(HighLevelWrapper(), "internal sealed class SasPairingRuntime");
        Assert.DoesNotMatch(Networking(), "AbiV1Constants.SAS_PAIRING_SOCKET_INVALID");
    }

    [Fact]
    public void PackageIdentityAndBuildSettings()
    {
        XElement project = XElement.Load(FrozenAbi.PathOf("dotnet", "src", "SasPairing", "SasPairing.csproj"));
        XElement props = XElement.Load(FrozenAbi.PathOf("dotnet", "Directory.Build.props"));
        string Property(XElement root, string name) => root.Descendants(name).Single().Value;

        Assert.Equal("SasPairing", Property(project, "PackageId"));
        Assert.Equal("SasPairing", Property(project, "RootNamespace"));
        Assert.Equal("SasPairing", Property(project, "AssemblyName"));
        Assert.Equal("0.1.0", Property(project, "VersionPrefix"));
        Assert.Equal("dev.1", Property(project, "VersionSuffix"));
        Assert.Equal("false", Property(project, "IsPackable"));
        Assert.Equal("true", Property(project, "AllowUnsafeBlocks"));
        Assert.Equal("true", Property(project, "GenerateDocumentationFile"));
        Assert.Empty(project.Descendants("PackageReference"));
        Assert.Equal("net10.0", Property(props, "TargetFramework"));
        Assert.Empty(props.Descendants("TargetFrameworks"));
        Assert.Equal("enable", Property(props, "Nullable"));
        Assert.Equal("enable", Property(props, "ImplicitUsings"));
        Assert.Equal("true", Property(props, "TreatWarningsAsErrors"));
        Assert.Equal("true", Property(props, "Deterministic"));
        Assert.Empty(props.Descendants("NoWarn"));
        Assert.Empty(project.Descendants("NoWarn"));

        Assert.Equal("SasPairing", Library.GetName().Name);
        Assert.Equal(".NETCoreApp,Version=v10.0", Library.GetCustomAttribute<TargetFrameworkAttribute>()!.FrameworkName);
        Assert.StartsWith("0.1.0-dev.1", Library.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion, StringComparison.Ordinal);
    }

    [Fact]
    public void NoNativeBinaryIsCommittedUnderDotnet()
    {
        string root = FrozenAbi.PathOf("dotnet");
        foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (relative.Contains("/bin/", StringComparison.Ordinal) || relative.Contains("/obj/", StringComparison.Ordinal) || relative.Contains("TestResults/", StringComparison.Ordinal))
            {
                continue;
            }

            Assert.False(relative.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || relative.EndsWith(".so", StringComparison.Ordinal) || relative.EndsWith(".dylib", StringComparison.Ordinal) || relative.EndsWith(".nupkg", StringComparison.Ordinal), relative);
        }
    }

    [Fact]
    public void TheDotnetWorkflowBuildsTheNativeArtifactFromThisCommitAndRunsEveryGate()
    {
        string workflow = File.ReadAllText(FrozenAbi.PathOf(".github", "workflows", "dotnet-package.yml"));
        int build = workflow.IndexOf("cargo build --manifest-path core/Cargo.toml --release --features native-abi", StringComparison.Ordinal);
        int test = workflow.IndexOf("dotnet test --no-build", StringComparison.Ordinal);
        Assert.True(build > 0 && test > build, "the native artifact must be built before the tests");
        foreach (string required in new[]
        {
            "windows-latest", "ubuntu-latest", "actions/setup-dotnet@v6", "global-json-file: dotnet/global.json",
            "dotnet restore --locked-mode", "dotnet build --no-restore -warnaserror", "dotnet format --verify-no-changes",
            "SAS_PAIRING_NATIVE_LIBRARY: ${{ github.workspace }}/core/target/release/${{ matrix.artifact }}",
            "sas_pairing_core.dll", "libsas_pairing_core.so", "tooling/check_abi_exports.py",
        })
        {
            Assert.Contains(required, workflow, StringComparison.Ordinal);
        }

        Assert.DoesNotContain("upload-artifact", workflow, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"dotnet (nuget )?push|dotnet pack"), workflow);
        Assert.Matches(new Regex(@"(?m)^permissions:\n  contents: read$"), workflow.Replace("\r\n", "\n", StringComparison.Ordinal));
    }

    [GeneratedRegex(@"\bpublic\s+(?:(?:static|sealed|abstract|readonly|unsafe|partial|ref|file)\s+)*(?:class|struct|interface|enum|record|delegate)\b")]
    private static partial Regex PublicTypeDeclaration();

    [GeneratedRegex(@"\bunsafe\b|delegate\s*\*|\bfixed\b|\bstackalloc\b|\bNativeLibrary\b|\bMarshal\.|\bUnsafe\.")]
    private static partial Regex UnsafeConstruct();

    [GeneratedRegex(@"\bunsafe\b")]
    private static partial Regex UnsafeKeyword();

    [GeneratedRegex(@"NativeLibrary\s*\.\s*Load\s*\([^)]*\)")]
    private static partial Regex NativeLibraryLoadCall();

    [GeneratedRegex(@"NativeLibrary\s*\.\s*(?:TryLoad|Load\s*\((?!path\)))")]
    private static partial Regex NativeLibraryAnyLoad();

    [GeneratedRegex(@"\bFree\s*\(|NativeLibrary\s*\.\s*Free")]
    private static partial Regex NativeLibraryFree();

    [GeneratedRegex(@"~\s*\w+\s*\(|\bSafeHandle\b|\bCriticalFinalizerObject\b|\bIDisposable\b|\bIAsyncDisposable\b|\bDispose\s*\(|\bProcessExit\b|\bUnloading\b|\bFreeLibrary\b|\bdlclose\b")]
    private static partial Regex FinalizerOrRelease();

    [GeneratedRegex(@"\[\s*(?:DllImport|LibraryImport)\b|\bextern\s+\w|\bSetDllImportResolver\b|\bResolvingUnmanagedDll\b|\bDllImportSearchPath\b|\bGetMainProgramHandle\b|\bDefaultDllImportSearchPaths\b")]
    private static partial Regex DefaultResolution();

    [GeneratedRegex(@"AppContext\s*\.\s*BaseDirectory|Environment\s*\.\s*CurrentDirectory|GetCurrentDirectory|GetEnvironmentVariable|GetFolderPath|Assembly\s*\.\s*(?:Location|GetExecutingAssembly)|\.Location\b|""PATH""|LD_LIBRARY_PATH|\bruntimes/|RuntimeIdentifier|HttpClient|WebClient|Process\s*\.\s*Start|""(?:lib)?sas_pairing_core|\.dll""|\.so""|AssemblyLoadContext|Directory\s*\.\s*(?:Enumerate|Get)Files")]
    private static partial Regex LibrarySearch();

    [GeneratedRegex(@"System\.Security\.Cryptography|\b(?:SHA\d+|HMAC\w*|Hkdf|HKDF|Aes\w*|ChaCha20\w*|ECDiffieHellman\w*|ECDsa|RSA\w*|RandomNumberGenerator|IncrementalHash|CryptographicOperations|X25519|Curve25519|Ed25519)\b")]
    private static partial Regex Cryptography();

    [GeneratedRegex(@"System\.Buffers\.Binary|\bBinaryPrimitives\b|\bBitConverter\b|\bEncoding\s*\.|\b(?:class|struct|record|interface)\s+\w*(?:Frame|Parser|Codec|Transcript|Mac|Sas|Deadline|Opportunit)\w*|\bDateTime\w*\b|\bStopwatch\b|\bTimeProvider\b|\bTickCount\w*\b|\bRandom\b")]
    private static partial Regex ProtocolCode();

    [GeneratedRegex(@"System\.Net\b|\bSocket\w*\b|\bTcp\w+\b|\bUdp\w+\b|\bIPEndPoint\b|\bIPAddress\b|\bDns\b|\bNetworkStream\b|\bWinsock\b|\bws2_32\b")]
    private static partial Regex Networking();

    [GeneratedRegex(@"\bnew\s+Thread\b|\bThread\s*\.|\bThreadPool\b|\bTask\s*\.\s*(?:Run|Factory|Delay)|\bParallel\s*\.|\bTimer\b|\bPeriodicTimer\b|\bBackgroundService\b|\basync\s|\bawait\s|\bChannel<")]
    private static partial Regex Threading();

    [GeneratedRegex(@"\b(?:class|struct|record|interface|enum)\s+SasPairing\w*|\b(?:class|struct|record|interface)\s+(?!sas_pairing_)\w*(?:Runtime|Authority|Host|Connection|Run|Ceremony|Result|Bootstrap|Listener|Presentation|Drive)\b")]
    private static partial Regex HighLevelWrapper();

    [GeneratedRegex(@"^(?:SasPairing\w*|\w*(?:Runtime|Authority|Host|Connection|Ceremony|Result|Bootstrap|Listener|Presentation|Network|Driver))$")]
    private static partial Regex HighLevelTypeName();
}
