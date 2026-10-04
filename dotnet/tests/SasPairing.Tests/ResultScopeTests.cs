using System.Reflection;
using System.Text.RegularExpressions;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-005 source and reflection guards over the production code (comments removed): the result service is
/// called only by the public result, a read is admitted as data access (never by the normal-operation admission)
/// and a dispose not at all, a read is one info and four copies with no loop, retry, or negotiation, no result
/// field is decoded, parsed, persisted, or trusted, no result can be polled, looked up, or enumerated, and the
/// source-proven bounds equal the frozen core.
/// </summary>
public sealed partial class ResultScopeTests
{
    private const string ResultFile = "SasPairingResult.cs";

    /// <summary>The production files that make up the result surface.</summary>
    private static readonly string[] ResultFiles = [ResultFile, "SasPairingResultData.cs", "SasPairingPeerRole.cs", "NativeNetworkRefs.cs", "Interop/FfiNativeResultApi.cs", "Interop/INativeResultApi.cs"];

    /// <summary>The body of the member of <paramref name="code"/> declared by <paramref name="signature"/> (up to the next member at the same indentation).</summary>
    private static string Body(string code, string signature)
    {
        int start = code.IndexOf(signature, StringComparison.Ordinal);
        Assert.True(start >= 0, signature);
        Match next = MemberStart().Match(code, start + signature.Length);
        return code[start..(next.Success ? next.Index : code.Length)];
    }

    [Fact]
    public void TheResultServiceIsCalledOnlyByThePublicResult()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            int calls = ServiceCall().Count(code);
            Assert.True(calls == (file == ResultFile ? 3 : 0), $"{file}: {calls} result service calls");
        }

        string result = ProductionSource.Code(ResultFile);
        Assert.Equal(["ResultCopy", "ResultDestroy", "ResultInfo"], ServiceCall().Matches(result).Select(m => m.Groups["call"].Value).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void ReadIsDataAccessAndDisposeIsNeverAdmissionChecked()
    {
        string result = ProductionSource.Code(ResultFile);
        string read = Body(result, "public SasPairingResultData Read()");
        string dispose = Body(result, "public void Dispose()");

        Assert.Single(Regex.Matches(read, @"\bContext\.AdmitData\(ReadOperation\)"));
        Assert.DoesNotContain("AdmitNormal", result, StringComparison.Ordinal);
        Assert.DoesNotContain("IsFatal", result, StringComparison.Ordinal);
        Assert.DoesNotContain("AdmitData", dispose, StringComparison.Ordinal);
        Assert.DoesNotContain("IsContractViolated", result, StringComparison.Ordinal);

        // The disposed check comes first in Read, and data admission checks only the contract latch.
        Assert.True(read.IndexOf("ObjectDisposedException.ThrowIf", StringComparison.Ordinal) < read.IndexOf("AdmitData", StringComparison.Ordinal));
        string admitData = Body(ProductionSource.Code("NativeProcessContext.cs"), "internal void AdmitData(string operation)");
        Assert.Contains("_contractViolation", admitData, StringComparison.Ordinal);
        Assert.DoesNotContain("IsFatal", admitData, StringComparison.Ordinal);
        Assert.DoesNotContain("_fatal", admitData, StringComparison.Ordinal);
    }

    [Fact]
    public void AReadIsOneInfoAndFourCopiesWithNoLoopRetryOrNegotiation()
    {
        string result = ProductionSource.Code(ResultFile);
        string read = Body(result, "public SasPairingResultData Read()");

        Assert.Single(Regex.Matches(result, @"\.ResultInfo\("));
        Assert.Single(Regex.Matches(result, @"\.ResultCopy\("));
        Assert.Equal(4, Regex.Count(read, @"\bCopy\("));
        Assert.Equal(1, Regex.Count(read, @"SAS_PAIRING_RESULT_FIELD_REQUEST_ID\b"));
        Assert.Equal(1, Regex.Count(read, @"SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP\b"));
        Assert.Equal(1, Regex.Count(read, @"SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT\b"));
        Assert.Equal(1, Regex.Count(read, @"SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER\b"));
        foreach (string file in ResultFiles.Where(f => f != "NativeNetworkRefs.cs"))
        {
            Assert.DoesNotMatch(Loop(), ProductionSource.Code(file));
        }

        // The service copies with exactly the capacity it is given: no +1, no slack, no size query.
        string ffi = ProductionSource.Code("Interop/FfiNativeResultApi.cs");
        Assert.Contains("new byte[capacity]", ffi, StringComparison.Ordinal);
        Assert.DoesNotMatch(new Regex(@"capacity\s*\+|\+\s*1\b"), ffi);
    }

    [Fact]
    public void NoResultFieldIsDecodedParsedPersistedOrTrusted()
    {
        foreach (string file in ResultFiles)
        {
            Match match = Interpretation().Match(ProductionSource.Code(file));
            Assert.False(match.Success, $"{file}: {match.Value}");
        }

        foreach (string file in ResultFiles.Concat(["SasPairingEvent.cs", "HostNetwork.cs", "SasPairingRuntime.cs"]))
        {
            Match match = Persistence().Match(ProductionSource.Code(file));
            Assert.False(match.Success, $"{file}: {match.Value}");
        }

        // The data snapshot holds only exact copies, never text.
        Assert.DoesNotContain(typeof(SasPairingResultData).GetProperties(), p => p.PropertyType == typeof(string) || p.PropertyType == typeof(char[]));
    }

    [Fact]
    public void NoResultCanBePolledLookedUpOrEnumerated()
    {
        // The only public member that yields a result is the event that delivered it.
        List<string> yielding = [];
        foreach (Type type in typeof(SasPairingRuntime).Assembly.GetExportedTypes())
        {
            foreach (MemberInfo member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                Type? produced = member switch
                {
                    MethodInfo m => m.ReturnType,
                    PropertyInfo p => p.PropertyType,
                    FieldInfo f => f.FieldType,
                    _ => null,
                };
                if (produced is not null && (produced == typeof(SasPairingResult) || (produced.IsGenericType && produced.GetGenericArguments().Contains(typeof(SasPairingResult))) || produced == typeof(SasPairingResult[])))
                {
                    yielding.Add($"{type.Name}.{member.Name}");
                }

                Assert.DoesNotMatch(PollingName(), member.Name);
            }
        }

        Assert.Equal(["SasPairingEvent.Result", "SasPairingEvent.get_Result"], yielding.Order(StringComparer.Ordinal));
        Assert.Null(typeof(SasPairingRuntime).GetProperty("ResultStore", BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void TheSourceProvenBoundsEqualTheFrozenCore()
    {
        string protocol = File.ReadAllText(FrozenAbi.PathOf("core", "src", "protocol.rs"));
        string ceremony = File.ReadAllText(FrozenAbi.PathOf("core", "src", "ceremony.rs"));

        uint Captured(Regex pattern, string text)
        {
            Match match = pattern.Match(text);
            Assert.True(match.Success, pattern.ToString());
            return uint.Parse(match.Groups[1].Value.Replace("_", "", StringComparison.Ordinal), System.Globalization.CultureInfo.InvariantCulture);
        }

        Assert.Equal(SasPairingResult.MaxRequestIdLength, Captured(new Regex(@"bounded\(request_id, 1, (\d+), ""request_id""\)"), protocol));
        Assert.Equal(SasPairingResult.MaxPeerBootstrapLength, Captured(new Regex(@"pub const MAX_BOOTSTRAP_FRAME: usize = ([\d_]+);"), protocol));
        Assert.Equal(SasPairingResult.MaxSharedContextLength, Captured(new Regex(@"bounded\(&self\.shared_context, 0, (\d+), ""shared_context""\)"), protocol));
        Match profile = new Regex(@"pub const PROFILE_ID: &\[u8\] = b""([^""]*)"";").Match(protocol);
        Assert.True(profile.Success);
        Assert.Equal(SasPairingResult.MaxProfileIdentifierLength, (uint)profile.Groups[1].Value.Length);

        // The result keeps exactly the profile constant, the canonical peer frame, and the peer's shared context.
        Assert.Contains("profile_identifier: protocol::PROFILE_ID,", ceremony, StringComparison.Ordinal);
        Assert.Contains("authenticated_peer_bootstrap: peer_bootstrap.canonical_bytes().to_vec(),", ceremony, StringComparison.Ordinal);
        Assert.Contains("authenticated_shared_context: peer_bootstrap.shared_context().to_vec(),", ceremony, StringComparison.Ordinal);
        Assert.Contains("encode_frame(\n            0x20,", protocol.Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal);
        Assert.Contains("MAX_BOOTSTRAP_FRAME,\n        )?;", protocol.Replace("\r\n", "\n", StringComparison.Ordinal), StringComparison.Ordinal);
        ulong headerBound = FrozenAbi.ParseLiteral(FrozenAbi.HeaderDefines().Single(d => d.Name == "SAS_PAIRING_MAX_REQUEST_ID_LEN").Literal);
        Assert.Equal(SasPairingResult.MaxRequestIdLength, headerBound);
    }

    [Fact]
    public void TheDetectorsMatchWhatTheyForbid()
    {
        Assert.Matches(ServiceCall(), "Context.Results.ResultCopy(_runtime.Handle");
        Assert.DoesNotMatch(ServiceCall(), "_functions.sas_pairing_result_copy(runtime");
        Assert.Matches(Loop(), "while (status == BufferTooSmall)");
        Assert.Matches(Loop(), "for (int attempt = 0; attempt < 2; attempt++)");
        Assert.Matches(Loop(), "goto retry;");
        foreach (string text in new[] { "Encoding.UTF8.GetString(bytes)", "new string(chars)", "Convert.ToBase64String(x)", "SasPairingBootstrap.Parse(x)", "Decode(bootstrap)", "IsTrusted", "Enroll(peer)" })
        {
            Assert.Matches(Interpretation(), text);
        }

        Assert.DoesNotMatch(Interpretation(), "_profileIdentifier = profileIdentifier.ToArray();");
        Assert.Matches(Persistence(), "File.WriteAllBytes(path, bootstrap)");
        Assert.Matches(Persistence(), "Registry.CurrentUser");
        Assert.Matches(Persistence(), "IsolatedStorageFile.GetUserStoreForApplication()");
        Assert.Matches(PollingName(), "GetResults");
        Assert.Matches(PollingName(), "PollResults");
        Assert.Matches(PollingName(), "FindResult");
        Assert.Matches(PollingName(), "ResultFromRequestId");
        Assert.DoesNotMatch(PollingName(), "Result");
        Assert.DoesNotMatch(PollingName(), "HasResult");
    }

    [GeneratedRegex(@"\bContext\.Results\.(?<call>\w+)\(")]
    private static partial Regex ServiceCall();

    [GeneratedRegex(@"\bwhile\s*\(|\bfor\s*\(|\bforeach\s*\(|\bgoto\b|\bdo\s*\{")]
    private static partial Regex Loop();

    [GeneratedRegex(@"\bEncoding\b|\bGetString\b|\bnew\s+string\s*\(|\bchar\b|\bUtf8\w*|\bAscii\w*|\bConvert\.|\bSasPairingBootstrap\b|\bParse\w*\(|\bDecode\w*\(|Trust\w*|Enroll\w*|Persist\w*|Commit\w*|Bilateral\w*")]
    private static partial Regex Interpretation();

    [GeneratedRegex(@"\bFile\s*\.|\bDirectory\s*\.|\bFileStream\b|\bRegistry\b|\bIsolatedStorage\w*|\bStreamWriter\b|\bPreferences\b")]
    private static partial Regex Persistence();

    [GeneratedRegex(@"^(?:Get|Poll|Find|List|Enumerate|All)\w*Results?$|^ResultFrom\w*$|^FindResult\w*$|^Results$")]
    private static partial Regex PollingName();

    [GeneratedRegex(@"(?m)^    (?:public|private|internal) ")]
    private static partial Regex MemberStart();
}
