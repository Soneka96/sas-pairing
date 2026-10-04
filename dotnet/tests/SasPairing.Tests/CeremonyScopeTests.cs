using System.Reflection;
using System.Text.RegularExpressions;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// P9-D-004 source and reflection guards over the production code (comments removed): every public ceremony
/// method makes exactly its own one native ceremony call and calls no other ceremony step, no drive, and no
/// recheck; nothing confirms a final ACK; no result is read, copied, or destroyed; the run keeps no write-pending
/// state, cached identity, or budget, and is not disposable.
/// </summary>
public sealed partial class CeremonyScopeTests
{
    private const string RunFile = "SasPairingRun.cs";

    /// <summary>Each public ceremony method of the run and the one service method it must call.</summary>
    private static readonly Dictionary<string, string> RunMethods = new()
    {
        ["AuthorizeExposure"] = "AuthorizeExposure",
        ["ExposeKey"] = "ExposeKey",
        ["Presentation"] = "Presentation",
        ["ApproveSas"] = "ApproveSas",
        ["EmitBootstrapMac"] = "EmitBootstrapMac",
        ["RejectSas"] = "RejectSas",
        ["CancelSas"] = "CancelSas",
        ["EmitInitiatorFinish"] = "EmitInitiatorFinish",
    };

    private static readonly string[] CeremonySteps = ["StartInitiator", .. RunMethods.Keys];

    /// <summary>The bodies of the public methods of <paramref name="code"/>, by name (up to the next member at the same indentation).</summary>
    private static Dictionary<string, string> PublicMethodBodies(string code)
    {
        Dictionary<string, string> bodies = [];
        foreach (Match member in PublicMethod().Matches(code))
        {
            int start = member.Index;
            Match next = MemberStart().Match(code, start + member.Length);
            bodies[member.Groups["name"].Value] = code[start..(next.Success ? next.Index : code.Length)];
        }

        return bodies;
    }

    [Fact]
    public void EveryRunMethodMakesExactlyItsOwnOneServiceCallAndChainsNothing()
    {
        Dictionary<string, string> bodies = PublicMethodBodies(ProductionSource.Code(RunFile));
        Assert.Equal(RunMethods.Keys.Order(StringComparer.Ordinal), bodies.Keys.Order(StringComparer.Ordinal));
        foreach ((string method, string body) in bodies)
        {
            string[] calls = [.. ServiceCall().Matches(body).Select(m => m.Groups["call"].Value)];
            Assert.Equal([RunMethods[method]], calls);
            foreach (string other in CeremonySteps)
            {
                // The method's own name appears in its signature only; every other step not at all.
                int expected = other == method ? 1 : 0;
                int found = Regex.Count(body, $@"(?<!api\.|Ceremony\.)\b{other}\s*\(");
                Assert.True(found == expected, $"{method} calls {other} ({found})");
            }

            Assert.DoesNotMatch(DriveCall(), body);
        }

        // The start: exactly one service call, in the one shared settlement file.
        string control = ProductionSource.Code("CeremonyControl.cs");
        Assert.Equal(["StartInitiator"], ServiceCall().Matches(control).Select(m => m.Groups["call"].Value));
        Assert.DoesNotMatch(DriveCall(), control);
        Assert.Single(Regex.Matches(ProductionSource.Code("SasPairingConnection.cs"), @"CeremonyControl\.Start\("));
    }

    [Fact]
    public void NoProductionCodeOutsideTheRunAndTheStartCallsTheCeremonyServiceOrAStep()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            if (file.StartsWith("Interop/", StringComparison.Ordinal) || file == "NativeProcessContext.cs")
            {
                continue;
            }

            int service = ServiceCall().Count(code);
            int expected = file switch
            {
                RunFile => RunMethods.Count,
                "CeremonyControl.cs" => 1,
                _ => 0,
            };
            Assert.True(service == expected, $"{file}: {service} ceremony service calls");

            // No helper anywhere invokes a public ceremony step of a run or a connection.
            Match step = StepInvocation().Match(code);
            Assert.False(step.Success, $"{file}: {step.Value}");
        }
    }

    [Fact]
    public void NothingConfirmsAFinalAckOrMarksAFrameWritten()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            foreach (Match declaration in MethodOrPropertyDeclaration().Matches(code))
            {
                Assert.DoesNotMatch(FinalAckName(), declaration.Groups["name"].Value);
            }

            Assert.DoesNotMatch(FinalAckName(), Path.GetFileNameWithoutExtension(file));
        }

        foreach (MemberInfo member in typeof(SasPairingRuntime).Assembly.GetTypes().SelectMany(t => t.GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly)))
        {
            if (member is MethodBase or PropertyInfo)
            {
                Assert.DoesNotMatch(FinalAckName(), member.Name);
            }
        }
    }

    [Fact]
    public void NoResultIsReadCopiedOrDestroyed()
    {
        foreach ((string file, string code) in ProductionSource.AllCode())
        {
            bool table = file == "Interop/AbiV1Exports.cs";
            Assert.True(table || !ResultExport().IsMatch(code), $"{file}: a result export");
        }

        Assert.DoesNotContain(typeof(SasPairingRuntime).Assembly.GetTypes(), t => t.Name is "INativeResultApi" or "FfiNativeResultApi" or "SasPairingResult");
        Assert.Null(typeof(SasPairingEvent).GetProperty("Result", BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void TheRunKeepsNoWritePendingStateCachedIdentityOrBudgetAndIsNotDisposable()
    {
        string[] fields = [.. typeof(SasPairingRun).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Select(f => f.Name).Order(StringComparer.Ordinal)];
        Assert.Equal(["<Ref>k__BackingField", "_connection"], fields);
        string[] refFields = [.. typeof(NativeRunRef).GetFields(BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).Select(f => f.Name).Order(StringComparer.Ordinal)];
        Assert.Equal(["<Handle>k__BackingField", "<IsValid>k__BackingField", "_requestId"], refFields);

        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(SasPairingRun)));
        Assert.Null(typeof(SasPairingRun).GetMethod("Dispose"));
        Assert.Null(typeof(SasPairingRun).GetMethod("Close"));
        Assert.Null(typeof(SasPairingRun).GetMethod("Finalize", BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly));
        Assert.Null(typeof(SasPairingRun).GetProperty("RequestId"));

        // The display is never compared by the package, and no step is decided by it.
        foreach ((string file, string code) in ProductionSource.AllCode().Where(f => f.File != "SasPairingSasPresentation.cs"))
        {
            Assert.DoesNotContain("DecimalDisplay", code, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheDetectorsMatchWhatTheyForbid()
    {
        Assert.Matches(ServiceCall(), "api.ExposeKey(target.Runtime");
        Assert.Matches(ServiceCall(), "Context.Ceremony.Presentation(target.Runtime");
        Assert.Matches(StepInvocation(), "run.ExposeKey();");
        Assert.Matches(StepInvocation(), "input.EmitBootstrapMac()");
        Assert.Matches(StepInvocation(), "connection.StartInitiator(local)");
        Assert.DoesNotMatch(StepInvocation(), "api.ExposeKey(target.Runtime");
        Assert.DoesNotMatch(StepInvocation(), "context.Ceremony.StartInitiator(");
        Assert.Matches(DriveCall(), "_connection.Host.Drive()");
        Assert.Matches(DriveCall(), "host.Network.Drive(operation, false)");
        Assert.Matches(DriveCall(), "RecheckAfterResume()");
        foreach (string name in new[] { "ConfirmFinalAck", "ConfirmSent", "AckSent", "FinishAck", "ConfirmFinish", "MarkFinalWritten", "MarkWritten", "CompleteFinish", "SendFinalAck" })
        {
            Assert.Matches(FinalAckName(), name);
        }

        Assert.DoesNotMatch(FinalAckName(), "EmitInitiatorFinish");
        Assert.DoesNotMatch(FinalAckName(), "ResponderFinishAck"); // the frozen protocol event value, not an API
        Assert.Matches(MethodOrPropertyDeclaration(), "public void ConfirmFinalAck()");
        Assert.Matches(MethodOrPropertyDeclaration(), "internal bool AckSent { get; }");
        Assert.Matches(ResultExport(), "_functions.sas_pairing_result_destroy(runtime, result)");
        Assert.DoesNotMatch(ResultExport(), "internal unsafe struct sas_pairing_result_info_t");
        Assert.Matches(PublicMethod(), "    public SasPairingLocalAction ExposeKey() =>");
        Assert.Matches(PublicMethod(), "    public SasPairingSasPresentation? Presentation()");
    }

    [GeneratedRegex(@"(?:\bapi|Context\.Ceremony|context\.Ceremony)\.(?<call>\w+)\(")]
    private static partial Regex ServiceCall();

    [GeneratedRegex(@"(?<!\bapi|Ceremony)\.(?:StartInitiator|AuthorizeExposure|ExposeKey|Presentation|ApproveSas|EmitBootstrapMac|RejectSas|CancelSas|EmitInitiatorFinish)\s*\(")]
    private static partial Regex StepInvocation();

    [GeneratedRegex(@"\bDrive\s*\(|\bRecheckAfterResume\s*\(")]
    private static partial Regex DriveCall();

    [GeneratedRegex(@"Confirm|FinalAck|AckSent|(?<!Responder|Initiator)FinishAck|MarkWritten|MarkFinal|CompleteFinish")]
    private static partial Regex FinalAckName();

    [GeneratedRegex(@"\b(?:public|internal|private|protected)\s+(?:(?:static|override|readonly|sealed|virtual|abstract|unsafe)\s+)*[\w<>\[\]?,.]+\s+(?<name>\w+)\s*(?:\(|\{|=>)")]
    private static partial Regex MethodOrPropertyDeclaration();

    [GeneratedRegex(@"\bsas_pairing_result_(?:info|copy|destroy)\b")]
    private static partial Regex ResultExport();

    [GeneratedRegex(@"(?m)^    public (?:SasPairingLocalAction|SasPairingSasPresentation\?) (?<name>\w+)\(")]
    private static partial Regex PublicMethod();

    [GeneratedRegex(@"(?m)^    (?:public|private|internal) ")]
    private static partial Regex MemberStart();
}
