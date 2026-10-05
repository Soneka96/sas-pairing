using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-006 distribution guards: distribution adds no loading path (the explicit absolute path stays the only way
/// to load the native library: no search, default, assembly-directory, <c>runtimes/</c>, or download lookup), adds
/// no public API, and the package-consumer smoke consumes the GENERATED package from a local feed only, never the
/// project.
/// </summary>
public sealed partial class DistributionScopeTests
{
    private static readonly Assembly Library = typeof(SasPairingRuntime).Assembly;

    [Fact]
    public void ProductionCodeHasNoAutomaticNativeLibraryLookupOrDownload()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            Match match = AutomaticLookup().Match(code);
            Assert.False(match.Success, $"{file}: automatic native lookup or download: \"{(match.Success ? match.Value : "")}\"");
        }
    }

    [Fact]
    public void TheExplicitFullyQualifiedPathRemainsTheOnlyLoaderInput()
    {
        // P9-D-001 D and P9-D-006: one Load of the validated canonical path; Create takes exactly that path.
        string loader = ProductionSource.Code("Interop/NativeLibraryLoader.cs");
        Assert.Contains("if (!Path.IsPathFullyQualified(libraryPath))", loader, StringComparison.Ordinal);
        Assert.Contains("NativeLibrary.Load(path)", loader, StringComparison.Ordinal);
        Assert.DoesNotContain("NativeLibrary.Free", loader, StringComparison.Ordinal);

        MethodInfo[] creators = [.. typeof(SasPairingRuntime).GetMethods(BindingFlags.Public | BindingFlags.Static).Where(m => m.DeclaringType == typeof(SasPairingRuntime))];
        MethodInfo create = Assert.Single(creators);
        Assert.Equal("Create", create.Name);
        ParameterInfo parameter = Assert.Single(create.GetParameters());
        Assert.Equal(typeof(string), parameter.ParameterType);
        Assert.Equal("nativeLibraryPath", parameter.Name);
        Assert.False(parameter.HasDefaultValue);
    }

    [Fact]
    public void DistributionAddsNoPublicTypeOrMember()
    {
        // The exact P9.5 public type set stays the whole surface (the member allowlist is PublicSurfaceTests).
        string[] exported = [.. Library.GetExportedTypes().Select(t => t.FullName!).Order(StringComparer.Ordinal)];
        Assert.Equal(ArchitectureTests.PublicTypes.Order(StringComparer.Ordinal), exported);
        foreach (Type type in Library.GetExportedTypes())
        {
            foreach (MemberInfo member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                Assert.DoesNotMatch(DistributionMemberName(), member.Name);
            }
        }
    }

    [Fact]
    public void ThePackageConsumerSmokeUsesTheGeneratedPackageFromALocalFeedOnly()
    {
        string directory = FrozenAbi.PathOf("dotnet", "tests", "SasPairing.PackageSmoke");
        XElement project = XElement.Load(Path.Combine(directory, "SasPairing.PackageSmoke.csproj"));
        Assert.Empty(project.Descendants("ProjectReference"));
        XElement package = Assert.Single(project.Descendants("PackageReference"));
        Assert.Equal("SasPairing", package.Attribute("Include")?.Value);
        Assert.Equal("0.1.0-dev.1", package.Attribute("Version")?.Value);
        Assert.Equal("false", project.Descendants("IsPackable").Single().Value);

        // Only the staged managed bundle as a source (nuget.org cleared), extracted into a project-local folder.
        XElement config = XElement.Load(Path.Combine(directory, "nuget.config"));
        XElement sources = config.Elements("packageSources").Single();
        Assert.Equal("clear", sources.Elements().First().Name.LocalName);
        XElement source = Assert.Single(sources.Elements("add"));
        Assert.Equal("../../../dist/sas-pairing-dotnet-nuget", source.Attribute("value")?.Value);
        Assert.Equal("obj/local-packages", config.Descendants("add").Single(e => e.Attribute("key")?.Value == "globalPackagesFolder").Attribute("value")?.Value);

        // Not part of the solution: it can be restored only after the package was packed and staged.
        string solution = File.ReadAllText(FrozenAbi.PathOf("dotnet", "SasPairing.sln"));
        Assert.DoesNotContain("PackageSmoke", solution, StringComparison.Ordinal);

        // It calls the public API only: no internal type, no test support, no reflection into the package.
        string program = File.ReadAllText(Path.Combine(directory, "Program.cs"));
        Assert.Contains("SasPairingRuntime.Create(args[0])", program, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"InternalsVisibleTo|SasPairing\.Interop|SasPairing\.Tests|NativeProcessContext|BindingFlags\.NonPublic"), program);
    }

    [Fact]
    public void TheDetectorsMatchWhatTheyForbid()
    {
        foreach (string forbidden in new[]
        {
            "NativeLibrary.Load(\"sas_pairing_core\")",
            "NativeLibrary.TryLoad(name, Assembly.GetExecutingAssembly(), null, out handle)",
            "Path.Combine(AppContext.BaseDirectory, \"runtimes\", \"win-x64\", \"native\", name)",
            "Path.Combine(AppDomain.CurrentDomain.BaseDirectory, name)",
            "Path.GetDirectoryName(typeof(SasPairingRuntime).Assembly.Location)",
            "Environment.ProcessPath",
            "Environment.GetEnvironmentVariable(\"SAS_PAIRING_NATIVE_LIBRARY\")",
            "\"runtimes/win-x64/native/sas_pairing_core.dll\"",
            "new HttpClient().GetByteArrayAsync(uri)",
            "\"https://github.com/Soneka96/sas-pairing/releases\"",
            "NativeLibrary.SetDllImportResolver(assembly, Resolve)",
            "RuntimeInformation.RuntimeIdentifier",
        })
        {
            Assert.Matches(AutomaticLookup(), forbidden);
        }

        Assert.DoesNotMatch(AutomaticLookup(), "NativeLibrary.Load(path)");
        Assert.DoesNotMatch(AutomaticLookup(), "if (!Path.IsPathFullyQualified(libraryPath))");
        Assert.Matches(DistributionMemberName(), "CreateDefault");
        Assert.Matches(DistributionMemberName(), "LoadBundledLibrary");
        Assert.Matches(DistributionMemberName(), "DownloadNative");
        Assert.DoesNotMatch(DistributionMemberName(), "Create");
    }

    [GeneratedRegex(@"NativeLibrary\s*\.\s*(?:TryLoad|Load\s*\((?!path\))|SetDllImportResolver)|AppContext\s*\.\s*BaseDirectory|AppDomain\s*\.\s*CurrentDomain|BaseDirectory|Assembly\s*\.\s*(?:Location|GetExecutingAssembly|GetEntryAssembly)|\.Location\b|Environment\s*\.\s*(?:ProcessPath|CurrentDirectory|GetEnvironmentVariable)|GetCurrentDirectory|""PATH""|\bruntimes[/\\""]|""runtimes|win-x64|RuntimeIdentifier|HttpClient|WebClient|https?://|DllImportSearchPath|""(?:lib)?sas_pairing_core")]
    private static partial Regex AutomaticLookup();

    [GeneratedRegex(@"^(?:CreateDefault|Load\w*|Download\w*|Bundled\w*|\w*NativeLibraryPath|\w*Resolve\w*|\w*Search\w*|Default\w*Path)$")]
    private static partial Regex DistributionMemberName();
}
