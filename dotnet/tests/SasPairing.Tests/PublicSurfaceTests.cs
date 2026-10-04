using System.Reflection;
using System.Text.RegularExpressions;
using SasPairing.Interop;

namespace SasPairing.Tests;

/// <summary>
/// The exact P9.3 public surface (P9-D-002, P9-D-003) by reflection: the 48 public statuses equal the frozen
/// constants, every public member is listed, and no public member exposes a native handle, socket value,
/// <c>SafeSocketHandle</c>, pointer, function pointer, native record, the binding, the loader, a native service,
/// or a run or result reference, or is a trust verdict.
/// </summary>
public sealed partial class PublicSurfaceTests
{
    private static readonly Assembly Library = typeof(SasPairingRuntime).Assembly;

    private const BindingFlags PublicMembers = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

    private static string Describe(MemberInfo member) => member switch
    {
        ConstructorInfo c => $".ctor({string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name))})",
        MethodInfo m => $"{(m.IsStatic ? "static " : "")}{m.ReturnType.Name} {m.Name}({string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name))})",
        PropertyInfo p => $"{p.PropertyType.Name} {p.Name}",
        FieldInfo f => $"{f.FieldType.Name} {f.Name}",
        _ => member.ToString()!,
    };

    [Fact]
    public void TheFortyEightPublicStatusesEqualTheFrozenConstantsExactly()
    {
        Dictionary<string, int> frozen = typeof(AbiV1Constants)
            .GetFields(BindingFlags.NonPublic | BindingFlags.Static)
            .Where(f => f.FieldType == typeof(int) && f.Name.StartsWith("SAS_PAIRING_", StringComparison.Ordinal))
            .ToDictionary(f => f.Name, f => (int)f.GetRawConstantValue()!);
        Assert.Equal(48, frozen.Count);

        SasPairingStatus[] statuses = Enum.GetValues<SasPairingStatus>();
        Assert.Equal(48, statuses.Length);
        Assert.Equal(48, statuses.Select(s => (int)s).Distinct().Count());
        Assert.Equal(typeof(int), Enum.GetUnderlyingType(typeof(SasPairingStatus)));
        foreach (SasPairingStatus status in statuses)
        {
            string native = "SAS_PAIRING_" + PascalBoundary().Replace(status.ToString(), "_$1").ToUpperInvariant();
            Assert.True(frozen.TryGetValue(native, out int value), $"{status} has no frozen constant {native}");
            Assert.Equal(value, (int)status);
        }

        Assert.Equal(frozen.Values.Order(), statuses.Select(s => (int)s).Order());
        Assert.Equal(0, (int)SasPairingStatus.Ok);
        Assert.Equal(405, (int)SasPairingStatus.ConnectionEnded);
        Assert.Equal(900, (int)SasPairingStatus.Fatal);
    }

    [Fact]
    public void AnExceptionKeepsEveryStatusCodeAndOnlyNineHundredIsFatal()
    {
        foreach (SasPairingStatus status in Enum.GetValues<SasPairingStatus>().Where(s => s != SasPairingStatus.Ok))
        {
            SasPairingNativeException known = new("op", (int)status, "m");
            Assert.Equal((int)status, known.StatusCode);
            Assert.Equal(status, known.KnownStatus);
            Assert.Equal(status == SasPairingStatus.Fatal, known.ProcessRestartRequired);
        }

        foreach (int unknown in new[] { -1, 5, 99, 108, 227, 301, 406, 777, 899, 901, int.MaxValue, int.MinValue })
        {
            SasPairingNativeException failure = new("op", unknown, "m");
            Assert.Equal(unknown, failure.StatusCode);
            Assert.Null(failure.KnownStatus);
            Assert.False(failure.ProcessRestartRequired);
        }
    }

    [Fact]
    public void TheAuthorityStateModelHasExactlyReadyBusyAndExhausted()
    {
        Assert.Equal(["Ready", "Busy", "Exhausted"], Enum.GetNames<SasPairingAuthorityState>());
        Assert.True(typeof(SasPairingAuthorityStatus).IsValueType);
        Assert.True(typeof(SasPairingAuthorityStatus).IsDefined(typeof(System.Runtime.CompilerServices.IsReadOnlyAttribute)));
        Assert.Equal(new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 3), new SasPairingAuthorityStatus(SasPairingAuthorityState.Ready, 3));
    }

    [Fact]
    public void EveryPublicMemberIsExactlyTheIntendedP93Surface()
    {
        static string[] Property(string type, string name) => [$"{type} {name}", $"{type} get_{name}()"];
        Dictionary<string, string[]> expected = new()
        {
            ["SasPairingRuntime"] = ["Boolean IsDisposed", "Boolean get_IsDisposed()", "static SasPairingRuntime Create(String)", "SasPairingAuthority RegisterAuthority(ReadOnlySpan`1)", "Void Dispose()"],
            ["SasPairingAuthority"] = ["Boolean IsDisposed", "Boolean get_IsDisposed()", "SasPairingAuthorityStatus GetStatus()", "SasPairingHost CreateHost()", "Void Dispose()"],
            ["SasPairingHost"] =
            [
                "Boolean IsDisposed", "Boolean get_IsDisposed()", "SasPairingHostNetworkState NetworkState", "SasPairingHostNetworkState get_NetworkState()",
                "Void AttachWindowsListener(SasPairingWindowsListenerSocket, SasPairingBootstrap, SasPairingBootstrap)", "Void DetachListener()",
                "SasPairingDriveBatch Drive()", "SasPairingDriveBatch RecheckAfterResume()", "Void Dispose()",
            ],
            ["SasPairingBootstrap"] =
            [
                ".ctor(ReadOnlySpan`1, ReadOnlySpan`1, ReadOnlySpan`1, ReadOnlySpan`1)",
                .. Property("ReadOnlySpan`1", "ApplicationIdentity"), .. Property("ReadOnlySpan`1", "KeyAlgorithm"),
                .. Property("ReadOnlySpan`1", "PublicKey"), .. Property("ReadOnlySpan`1", "SharedContext"),
            ],
            ["SasPairingWindowsListenerSocket"] = ["static SasPairingWindowsListenerSocket FromSocket(Socket)", .. Property("Boolean", "IsTransferred"), "Void Dispose()"],
            ["SasPairingConnection"] = [.. Property("Boolean", "IsDisposed"), "Void Dispose()"],
            ["SasPairingDriveBatch"] = [.. Property("IReadOnlyList`1", "Events"), .. Property("SasPairingDriveFailure", "Failure")],
            ["SasPairingDriveFailure"] = [.. Property("Int32", "StatusCode"), .. Property("Nullable`1", "KnownStatus"), .. Property("Boolean", "ProcessRestartRequired")],
            ["SasPairingEvent"] =
            [
                .. Property("SasPairingEventKind", "Kind"), .. Property("SasPairingConnection", "Connection"), .. Property("SasPairingStepKind", "StepKind"),
                .. Property("SasPairingProtocolEvent", "ProtocolEvent"), .. Property("SasPairingEventReason", "Reason"), .. Property("SasPairingDeadlineKind", "DeadlineKind"),
                .. Property("SasPairingCancelState", "CancelState"), .. Property("SasPairingCancelReason", "CancelReason"), .. Property("Boolean", "WritePending"),
                .. Property("Boolean", "RunUntracked"), .. Property("ReadOnlySpan`1", "RequestId"), .. Property("Boolean", "HasTrackedRun"),
                .. Property("Boolean", "HasResult"), .. Property("Boolean", "ShouldDisposeConnection"),
            ],
            ["SasPairingInitializationException"] = ["SasPairingInitializationFailure Failure", "SasPairingInitializationFailure get_Failure()", "Boolean ProcessRestartRequired", "Boolean get_ProcessRestartRequired()"],
            ["SasPairingNativeException"] =
            [
                "String Operation", "String get_Operation()", "Int32 StatusCode", "Int32 get_StatusCode()", "Nullable`1 KnownStatus", "Nullable`1 get_KnownStatus()",
                "Boolean ProcessRestartRequired", "Boolean get_ProcessRestartRequired()",
            ],
            ["SasPairingContractException"] = ["String Operation", "String get_Operation()", "Boolean ProcessRestartRequired", "Boolean get_ProcessRestartRequired()"],
            ["SasPairingAuthorityStatus"] =
            [
                ".ctor(SasPairingAuthorityState, UInt32)", "SasPairingAuthorityState State", "SasPairingAuthorityState get_State()", "Void set_State(SasPairingAuthorityState)",
                "UInt32 RemainingOpportunities", "UInt32 get_RemainingOpportunities()", "Void set_RemainingOpportunities(UInt32)", "String ToString()",
                "static Boolean op_Inequality(SasPairingAuthorityStatus, SasPairingAuthorityStatus)", "static Boolean op_Equality(SasPairingAuthorityStatus, SasPairingAuthorityStatus)",
                "Int32 GetHashCode()", "Boolean Equals(Object)", "Boolean Equals(SasPairingAuthorityStatus)", "Void Deconstruct(SasPairingAuthorityState&, UInt32&)",
            ],
        };

        foreach (Type type in Library.GetExportedTypes().Where(t => !t.IsEnum))
        {
            string[] actual = [.. type.GetMembers(PublicMembers).Select(Describe).Order(StringComparer.Ordinal)];
            Assert.True(expected.TryGetValue(type.Name, out string[]? members), $"unexpected public type {type}");
            Assert.Equal(members!.Order(StringComparer.Ordinal), actual);
        }

        Assert.Equal(expected.Keys.Order(StringComparer.Ordinal), Library.GetExportedTypes().Where(t => !t.IsEnum).Select(t => t.Name).Order(StringComparer.Ordinal));

        // No public constructor on the wrappers, the exceptions, or the network outputs: only the library creates
        // them (the Bootstrap is the one input with a public constructor; the token has a factory).
        foreach (Type type in new[]
        {
            typeof(SasPairingRuntime), typeof(SasPairingAuthority), typeof(SasPairingHost), typeof(SasPairingInitializationException), typeof(SasPairingNativeException),
            typeof(SasPairingContractException), typeof(SasPairingWindowsListenerSocket), typeof(SasPairingConnection), typeof(SasPairingDriveBatch),
            typeof(SasPairingDriveFailure), typeof(SasPairingEvent),
        })
        {
            Assert.Empty(type.GetConstructors());
        }
    }

    [Fact]
    public void NoPublicMemberExposesARawInteropConceptOrATrustVerdict()
    {
        Type[] forbiddenTypes =
        [
            typeof(ulong), typeof(long), typeof(nint), typeof(nuint), typeof(NativeAbiV1), typeof(AbiV1FunctionTable), typeof(NativeAbiV1Loader), typeof(INativeLifecycleApi),
            typeof(INativeNetworkApi), typeof(NativeProcessContext), typeof(NativeInitializationException), typeof(System.Runtime.InteropServices.SafeHandle),
            typeof(System.Net.Sockets.SafeSocketHandle), typeof(NativeRunRef), typeof(NativeResultRef), typeof(NativeResultStore), typeof(NativeEventRecord),
            typeof(NativeBootstrapBytes), typeof(HostNetwork), typeof(IListenerSocketResource), typeof(byte[]), typeof(Memory<byte>), typeof(ArraySegment<byte>),
        ];
        foreach (Type type in Library.GetExportedTypes())
        {
            if (type.IsEnum)
            {
                // Enum members are values (the mandated UnsupportedPointerWidth names a pointer width, not a
                // pointer); none may still be a trust verdict.
                Assert.All(Enum.GetNames(type), name => Assert.DoesNotMatch(TrustVerdictName(), name));
                continue;
            }

            foreach (MemberInfo member in type.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                Assert.DoesNotMatch(ForbiddenMemberName(), member.Name);
                IEnumerable<Type> types = member switch
                {
                    MethodBase m => m.GetParameters().Select(p => p.ParameterType).Concat(m is MethodInfo mi ? [mi.ReturnType] : []),
                    PropertyInfo p => [p.PropertyType],
                    FieldInfo f => [f.FieldType],
                    EventInfo e => [e.EventHandlerType!],
                    _ => [],
                };
                foreach (Type used in types.Select(t => t.HasElementType ? t.GetElementType()! : t))
                {
                    string where = $"{type.Name}.{member.Name}: {used}";
                    Assert.False(used.IsPointer || used.IsFunctionPointer || used.IsUnmanagedFunctionPointer, where);
                    Assert.DoesNotContain(used, forbiddenTypes);
                    Assert.NotEqual("SasPairing.Interop", used.Namespace);
                    Assert.False(used.Name.StartsWith("sas_pairing_", StringComparison.Ordinal), where);
                    Assert.False(used.IsGenericType && used.GetGenericArguments().Any(a => forbiddenTypes.Contains(a)), where);

                    // The caller's Socket is accepted by the token factory only; it is never returned or stored publicly.
                    Assert.True(used != typeof(System.Net.Sockets.Socket) || (type == typeof(SasPairingWindowsListenerSocket) && member.Name == "FromSocket" && member is MethodInfo { ReturnType: var r } && r != used), where);
                }
            }
        }

        Assert.All(Library.GetExportedTypes(), t => Assert.False(t.IsDefined(typeof(System.Runtime.CompilerServices.UnsafeValueTypeAttribute))));
    }

    [Fact]
    public void TheForbiddenNameDetectorMatchesWhatItForbids()
    {
        foreach (string name in new[] { "Handle", "NativeHandle", "RawHandle", "get_NativeHandle", "Pointer", "IsAttack", "IsMaliciousPeer", "PeerTrusted", "AuthenticationCompromised", "ShouldTrust", "Reset", "ResetForTesting", "ClearFatal", "Recover", "Reload", "Reinitialize", "LoadAnotherLibrary", "Close" })
        {
            Assert.Matches(ForbiddenMemberName(), name);
        }

        Assert.DoesNotMatch(ForbiddenMemberName(), "Dispose");
        Assert.DoesNotMatch(ForbiddenMemberName(), "ProcessRestartRequired");
    }

    [GeneratedRegex(@"(?<=[a-z0-9])([A-Z])")]
    private static partial Regex PascalBoundary();

    [GeneratedRegex(@"Handle|Pointer|Attack|Malicious|Trust|Compromis|^(?:Reset\w*|ClearFatal|Recover|Reload|Reinitialize|LoadAnotherLibrary|Close)$")]
    private static partial Regex ForbiddenMemberName();

    [GeneratedRegex(@"Attack|Malicious|Trust|Compromis|Verdict")]
    private static partial Regex TrustVerdictName();
}
