using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9.1 and P9.2 architecture and scope guards over the production sources (comments removed) and the built
/// assembly: raw interop private and localized under <c>Interop/</c>, one explicit-path load and no release of
/// the image, no library search, exactly the P9.2 public lifecycle surface (P9-D-002) with deterministic
/// disposal and no finalizer, and nothing of later increments, the protocol, cryptography, networking, or
/// threads.
/// </summary>
public sealed partial class ArchitectureTests
{
    private static readonly Assembly Library = typeof(AbiV1Constants).Assembly;

    /// <summary>The exact P9.2 public surface (P9-D-002): nothing else is public.</summary>
    internal static readonly string[] PublicTypes =
    [
        "SasPairing.SasPairingAuthority",
        "SasPairing.SasPairingAuthorityState",
        "SasPairing.SasPairingAuthorityStatus",
        "SasPairing.SasPairingContractException",
        "SasPairing.SasPairingHost",
        "SasPairing.SasPairingInitializationException",
        "SasPairing.SasPairingInitializationFailure",
        "SasPairing.SasPairingNativeException",
        "SasPairing.SasPairingRuntime",
        "SasPairing.SasPairingStatus",
    ];

    /// <summary>The three lifecycle wrappers: the only production files that may implement disposal.</summary>
    private static readonly string[] LifecycleFiles = ["SasPairingAuthority.cs", "SasPairingHost.cs", "SasPairingRuntime.cs"];

    private static void AssertAbsent(Regex pattern, string what)
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            Match match = pattern.Match(code);
            Assert.False(match.Success, $"{file}: {what}: \"{(match.Success ? match.Value : "")}\"");
        }
    }

    [Fact]
    public void TheAssemblyExportsExactlyTheP92PublicSurface()
    {
        // P9.1 exported nothing; P9.2 adds exactly the lifecycle, status, and error types (P9-D-002).
        Assert.Equal(PublicTypes, Library.GetExportedTypes().Select(t => t.FullName!).Order(StringComparer.Ordinal));
        Assert.Equal(PublicTypes, Library.GetTypes().Where(t => t.IsPublic).Select(t => t.FullName!).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(Library.GetExportedTypes(), t => t.Namespace != "SasPairing");
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
    public void PublicTypesAreDeclaredOnlyInTheirOwnFilesOutsideInterop()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            string[] declared = [.. PublicTypeDeclarationName().Matches(code).Select(m => m.Groups["name"].Value)];
            if (file.StartsWith("Interop/", StringComparison.Ordinal) || file == "NativeProcessContext.cs")
            {
                Assert.True(declared.Length == 0, $"{file}: raw interop and the process context declare no public type: {string.Join(", ", declared)}");
            }
            else
            {
                Assert.Equal([Path.GetFileNameWithoutExtension(file)], declared);
            }
        }
    }

    [Fact]
    public void SourceLayoutIsTheRawInteropPlusTheP92LifecycleWrapper()
    {
        string[] interop =
        [
            "Interop/AbiV1Constants.cs", "Interop/AbiV1Exports.cs", "Interop/AbiV1Structs.cs", "Interop/FfiNativeLifecycleApi.cs",
            "Interop/INativeLifecycleApi.cs", "Interop/NativeAbiV1.cs", "Interop/NativeInitializationFailure.cs", "Interop/NativeLibraryLoader.cs",
        ];
        string[] root = [.. PublicTypes.Select(t => t["SasPairing.".Length..] + ".cs").Append("NativeProcessContext.cs")];
        Assert.Equal([.. root.Concat(interop).Order(StringComparer.Ordinal)], ProductionSource.Files());
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
        AssertAbsent(FinalizerOrRelease(), "a finalizer, SafeHandle, or shutdown release");
    }

    [Fact]
    public void OnlyTheThreeLifecycleWrappersAreDisposableAndNothingHasAFinalizer()
    {
        // P9-D-002: deterministic IDisposable on Runtime, Authority, and Host only; the loader, the image, the
        // binding, the process context, and the lifecycle service are never disposed.
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            bool lifecycle = LifecycleFiles.Contains(file);
            Assert.True(lifecycle || !Disposal().IsMatch(code), $"{file}: disposal outside the three lifecycle wrappers");
            if (lifecycle)
            {
                Assert.Matches(@"public sealed class \w+ : IDisposable\b", code);
                Assert.Single(DisposeDeclaration().Matches(code));
            }
        }

        string[] disposable = [.. Library.GetTypes().Where(t => typeof(IDisposable).IsAssignableFrom(t)).Select(t => t.Name).Order(StringComparer.Ordinal)];
        Assert.Equal(["SasPairingAuthority", "SasPairingHost", "SasPairingRuntime"], disposable);
        foreach (Type type in Library.GetTypes())
        {
            Assert.Null(type.GetMethod("Finalize", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly));
            Assert.False(typeof(SafeHandle).IsAssignableFrom(type), type.FullName);
            Assert.False(typeof(System.Runtime.ConstrainedExecution.CriticalFinalizerObject).IsAssignableFrom(type), type.FullName);
        }
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
    public void ProductionDeclaresNoWrapperOfALaterIncrement()
    {
        // P9.2 allows the Runtime, Authority, and Host lifecycle; listeners, networking, connections, runs,
        // ceremony control, SAS presentation, results, and Bootstrap belong to P9.3-P9.5.
        AssertAbsent(LaterIncrementWrapper(), "a network, listener, connection, run, ceremony, SAS, Bootstrap, or result wrapper");
        string[] types = [.. Library.GetTypes().Where(t => !t.Name.StartsWith('<')).Select(t => t.Name)];
        foreach (string name in types)
        {
            Assert.DoesNotMatch(LaterIncrementTypeName(), name);
            if (name.StartsWith("SasPairing", StringComparison.Ordinal))
            {
                Assert.Contains("SasPairing." + name, PublicTypes);
            }
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
        Assert.Matches(PublicTypeDeclarationName(), "public sealed unsafe class AbiV1FunctionTable");
        Assert.Matches(PublicTypeDeclarationName(), "public readonly record struct SasPairingAuthorityStatus(");
        Assert.Matches(FinalizerOrRelease(), "~Loader() { }");
        Assert.Matches(FinalizerOrRelease(), "~SasPairingRuntime()");
        Assert.Matches(FinalizerOrRelease(), "internal sealed class LifecycleHandle : SafeHandle");
        Assert.Matches(Disposal(), "internal sealed class NativeAbiV1 : IDisposable");
        Assert.Matches(Disposal(), "public void Dispose() { }");
        Assert.Matches(Networking(), "new TcpListener(address, 0)");
        Assert.Matches(Threading(), "new Timer(callback)");
        Assert.Matches(Cryptography(), "using System.Security.Cryptography;");
        Assert.Matches(Threading(), "public Task<SasPairingRuntime> CreateAsync()");
        Assert.Matches(Threading(), "ValueTask Run()");
        Assert.Matches(ProtocolCode(), "Encoding.UTF8.GetBytes(scope)");
        Assert.Matches(ProtocolCode(), "internal sealed class SasPresentation");
        Assert.DoesNotMatch(ProtocolCode(), "public sealed class SasPairingRuntime : IDisposable");
        Assert.Matches(LaterIncrementWrapper(), "public sealed class SasPairingConnection");
        Assert.Matches(LaterIncrementWrapper(), "public sealed class SasPairingBootstrap");
        Assert.Matches(LaterIncrementWrapper(), "public sealed class SasPairingResult");
        Assert.Matches(LaterIncrementWrapper(), "public sealed class SasPairingRun");
        Assert.Matches(LaterIncrementWrapper(), "internal sealed class WindowsListener");
        Assert.DoesNotMatch(LaterIncrementWrapper(), "public sealed class SasPairingRuntime : IDisposable");
        Assert.DoesNotMatch(LaterIncrementWrapper(), "public sealed class SasPairingHost : IDisposable");
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

    [GeneratedRegex(@"\bpublic\s+(?:(?:static|sealed|abstract|readonly|unsafe|partial|ref|file)\s+)*(?:class|struct|interface|enum|record(?:\s+(?:struct|class))?|delegate)\s+(?<name>\w+)")]
    private static partial Regex PublicTypeDeclarationName();

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

    [GeneratedRegex(@"~\s*\w+\s*\(|\bSafeHandle\b|\bCriticalFinalizerObject\b|\bIAsyncDisposable\b|\bProcessExit\b|\bUnloading\b|\bFreeLibrary\b|\bdlclose\b")]
    private static partial Regex FinalizerOrRelease();

    [GeneratedRegex(@"\bIDisposable\b|\bDispose\s*\(|\bSuppressFinalize\b")]
    private static partial Regex Disposal();

    [GeneratedRegex(@"\bpublic void Dispose\(\)")]
    private static partial Regex DisposeDeclaration();

    [GeneratedRegex(@"\[\s*(?:DllImport|LibraryImport)\b|\bextern\s+\w|\bSetDllImportResolver\b|\bResolvingUnmanagedDll\b|\bDllImportSearchPath\b|\bGetMainProgramHandle\b|\bDefaultDllImportSearchPaths\b")]
    private static partial Regex DefaultResolution();

    [GeneratedRegex(@"AppContext\s*\.\s*BaseDirectory|Environment\s*\.\s*CurrentDirectory|GetCurrentDirectory|GetEnvironmentVariable|GetFolderPath|Assembly\s*\.\s*(?:Location|GetExecutingAssembly)|\.Location\b|""PATH""|LD_LIBRARY_PATH|\bruntimes/|RuntimeIdentifier|HttpClient|WebClient|Process\s*\.\s*Start|""(?:lib)?sas_pairing_core|\.dll""|\.so""|AssemblyLoadContext|Directory\s*\.\s*(?:Enumerate|Get)Files")]
    private static partial Regex LibrarySearch();

    [GeneratedRegex(@"System\.Security\.Cryptography|\b(?:SHA\d+|HMAC\w*|Hkdf|HKDF|Aes\w*|ChaCha20\w*|ECDiffieHellman\w*|ECDsa|RSA\w*|RandomNumberGenerator|IncrementalHash|CryptographicOperations|X25519|Curve25519|Ed25519)\b")]
    private static partial Regex Cryptography();

    [GeneratedRegex(@"System\.Buffers\.Binary|\bBinaryPrimitives\b|\bBitConverter\b|\bEncoding\s*\.|\b(?:class|struct|record|interface)\s+\w*(?:Frame|Parser|Codec|Transcript|Mac|Sas(?!Pairing)|Deadline|Opportunit)\w*|\bDateTime\w*\b|\bStopwatch\b|\bTimeProvider\b|\bTickCount\w*\b|\bRandom\b")]
    private static partial Regex ProtocolCode();

    [GeneratedRegex(@"System\.Net\b|\bSocket\w*\b|\bTcp\w+\b|\bUdp\w+\b|\bIPEndPoint\b|\bIPAddress\b|\bDns\b|\bNetworkStream\b|\bWinsock\b|\bws2_32\b")]
    private static partial Regex Networking();

    [GeneratedRegex(@"\bnew\s+Thread\b|\bThread\s*\.|\bThreadPool\b|\bTask\s*\.\s*(?:Run|Factory|Delay)|\bParallel\s*\.|\bTimer\b|\bPeriodicTimer\b|\bBackgroundService\b|\basync\s|\bawait\s|\bChannel<|\b(?:Value)?Task\b")]
    private static partial Regex Threading();

    [GeneratedRegex(@"\b(?:class|struct|record|interface|enum)\s+(?!sas_pairing_)\w*(?:Connection|Run|Ceremony|Result|Bootstrap|Listener|Presentation|Drive|Driver|Network|Event|Socket)\b")]
    private static partial Regex LaterIncrementWrapper();

    [GeneratedRegex(@"^\w*(?:Connection|Run|Ceremony|Result|Bootstrap|Listener|Presentation|Network|Driver|Event|Socket)$")]
    private static partial Regex LaterIncrementTypeName();
}
