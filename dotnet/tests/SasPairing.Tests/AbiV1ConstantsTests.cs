using System.Reflection;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// Every frozen ABI v1 constant of the private interop layer against the manifest (sections 1, 3, 4, 5) and
/// the header: same names, no missing or extra constant, same values, and the P9-D-001 C# type of each.
/// </summary>
public sealed class AbiV1ConstantsTests
{
    /// <summary>The private constants: name to (declared type, value as an unsigned 64-bit pattern).</summary>
    private static Dictionary<string, (Type Type, ulong Value)> DeclaredConstants()
    {
        Dictionary<string, (Type, ulong)> constants = [];
        foreach (FieldInfo field in typeof(AbiV1Constants).GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
        {
            object value = field.IsLiteral ? field.GetRawConstantValue()! : field.GetValue(null)!;
            constants.Add(field.Name, (field.FieldType, AsPattern(value)));
        }

        foreach (PropertyInfo property in typeof(AbiV1Constants).GetProperties(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
        {
            constants.Add(property.Name, (property.PropertyType, AsPattern(property.GetValue(null)!)));
        }

        return constants;
    }

    private static ulong AsPattern(object value) => value switch
    {
        int v => unchecked((ulong)v),
        uint v => v,
        ulong v => v,
        nuint v => v,
        _ => throw new InvalidOperationException($"Unexpected constant type {value.GetType()}"),
    };

    private static ulong ManifestValue(string value) =>
        value == "UINTPTR_MAX" ? nuint.MaxValue : FrozenAbi.ParseLiteral(value);

    [Fact]
    public void TheConstantSetIsExactlyTheManifestConstantSet()
    {
        HashSet<string> manifest =
        [
            .. FrozenAbi.ManifestVersion().Select(r => r.Name),
            .. FrozenAbi.ManifestStatuses().Select(r => r.Name),
            .. FrozenAbi.ManifestNamespaces().Select(r => r.Name),
            .. FrozenAbi.ManifestScalars().Select(r => r.Name),
        ];
        Assert.Equal(2 + 48 + 84 + 11, manifest.Count);
        Assert.Equal(manifest.Order(StringComparer.Ordinal), DeclaredConstants().Keys.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void TheAbiVersionIsExactlyOneAndZeroIsInvalid()
    {
        Assert.Equal(1u, AbiV1Constants.SAS_PAIRING_ABI_VERSION);
        Assert.Equal(0u, AbiV1Constants.SAS_PAIRING_ABI_VERSION_INVALID);
        Dictionary<string, (Type Type, ulong Value)> declared = DeclaredConstants();
        foreach ((string name, string value) in FrozenAbi.ManifestVersion())
        {
            Assert.Equal(typeof(uint), declared[name].Type);
            Assert.Equal(ManifestValue(value), declared[name].Value);
        }

        Assert.Contains(FrozenAbi.HeaderDefines(), d => d.Name == "SAS_PAIRING_ABI_VERSION" && FrozenAbi.ParseLiteral(d.Literal) == AbiV1Constants.SAS_PAIRING_ABI_VERSION);
    }

    [Fact]
    public void AllFortyEightStatusesExistExactlyOnceWithTheirFrozenValues()
    {
        IReadOnlyList<(string Name, string Value)> manifest = FrozenAbi.ManifestStatuses();
        Assert.Equal(48, manifest.Count);
        Dictionary<string, (Type Type, ulong Value)> declared = DeclaredConstants();
        List<KeyValuePair<string, (Type Type, ulong Value)>> statuses = [.. declared.Where(c => c.Value.Type == typeof(int))];
        Assert.Equal(48, statuses.Count);
        Assert.Equal(48, statuses.Select(s => s.Value.Value).Distinct().Count());
        foreach ((string name, string value) in manifest)
        {
            Assert.True(declared.ContainsKey(name), $"missing status {name}");
            Assert.Equal(typeof(int), declared[name].Type);
            Assert.Equal(ManifestValue(value), declared[name].Value);
        }

        // Spot pins of values a reviewer names explicitly; the manifest comparison above covers all 48.
        Assert.Equal(0, AbiV1Constants.SAS_PAIRING_OK);
        Assert.Equal(205, AbiV1Constants.SAS_PAIRING_WRITE_PENDING);
        Assert.Equal(900, AbiV1Constants.SAS_PAIRING_FATAL);
    }

    [Fact]
    public void StatusRangesMatchTheFrozenNamespace()
    {
        int[] values = [.. FrozenAbi.ManifestStatuses().Select(s => (int)FrozenAbi.ParseLiteral(s.Value)).Order()];
        int[] expected = [0, .. Enumerable.Range(1, 4), .. Enumerable.Range(100, 8), .. Enumerable.Range(200, 27), 300, .. Enumerable.Range(400, 6), 900];
        Assert.Equal(expected, values);
    }

    [Fact]
    public void EveryNamespaceValueMatchesTheManifestAsUint32()
    {
        IReadOnlyList<(string Name, string CType, string Value)> manifest = FrozenAbi.ManifestNamespaces();
        Assert.Equal(84, manifest.Count);
        Assert.Equal(13, manifest.Select(r => r.CType).Distinct().Count());
        IReadOnlyDictionary<string, string> types = FrozenAbi.ManifestTypes();
        Dictionary<string, (Type Type, ulong Value)> declared = DeclaredConstants();
        foreach ((string name, string cType, string value) in manifest)
        {
            Assert.Equal("uint32_t", types[cType]);
            Assert.Equal(AbiTypeMap.ToClr(cType), declared[name].Type);
            Assert.Equal(typeof(uint), declared[name].Type);
            Assert.Equal(ManifestValue(value), declared[name].Value);
        }

        // Flags are bit masks; result fields start at 1 (0 names no field).
        Assert.Equal(0x1u, AbiV1Constants.SAS_PAIRING_EVENT_FLAG_WRITE_PENDING);
        Assert.Equal(0x2u, AbiV1Constants.SAS_PAIRING_EVENT_FLAG_RUN_UNTRACKED);
        Assert.Equal(0x1u, AbiV1Constants.SAS_PAIRING_ACTION_FLAG_WRITE_PENDING);
        Assert.Equal([1u, 2u, 3u, 4u], [AbiV1Constants.SAS_PAIRING_RESULT_FIELD_REQUEST_ID, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_PEER_BOOTSTRAP, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_AUTHENTICATED_SHARED_CONTEXT, AbiV1Constants.SAS_PAIRING_RESULT_FIELD_PROFILE_IDENTIFIER]);
    }

    [Fact]
    public void HandleInvalidValuesAndScalarLimitsMatchTheManifestWithPointerSizedTypes()
    {
        IReadOnlyList<(string Name, string CType, string Value)> manifest = FrozenAbi.ManifestScalars();
        Assert.Equal(11, manifest.Count);
        Dictionary<string, (Type Type, ulong Value)> declared = DeclaredConstants();
        foreach ((string name, string cType, string value) in manifest)
        {
            Assert.Equal(AbiTypeMap.ToClr(cType), declared[name].Type);
            Assert.Equal(ManifestValue(value), declared[name].Value);
        }

        foreach (string handle in new[] { "RUNTIME", "AUTHORITY", "HOST", "CONNECTION", "RUN", "RESULT" })
        {
            Assert.Equal((typeof(ulong), 0ul), declared[$"SAS_PAIRING_{handle}_INVALID"]);
        }

        // size_t limits and the uintptr_t socket are pointer-sized (nuint), never ulong.
        Assert.Equal(typeof(nuint), declared["SAS_PAIRING_SOCKET_INVALID"].Type);
        Assert.Equal(nuint.MaxValue, AbiV1Constants.SAS_PAIRING_SOCKET_INVALID);
        Assert.Equal((nuint)17, AbiV1Constants.SAS_PAIRING_MAX_DRIVE_EVENTS);
        Assert.Equal((nuint)64, AbiV1Constants.SAS_PAIRING_MAX_REQUEST_ID_LEN);
        Assert.Equal((nuint)32, AbiV1Constants.SAS_PAIRING_MAX_RUNS_PER_CONNECTION);
        Assert.Equal((nuint)14, AbiV1Constants.SAS_PAIRING_SAS_DECIMAL_LEN);
        foreach (string limit in new[] { "SAS_PAIRING_MAX_DRIVE_EVENTS", "SAS_PAIRING_MAX_REQUEST_ID_LEN", "SAS_PAIRING_MAX_RUNS_PER_CONNECTION", "SAS_PAIRING_SAS_DECIMAL_LEN" })
        {
            Assert.Equal(typeof(nuint), declared[limit].Type);
        }
    }

    [Fact]
    public void EveryHeaderDefineMatchesTheDeclaredConstantAndType()
    {
        Dictionary<string, (Type Type, ulong Value)> declared = DeclaredConstants();
        IReadOnlyList<(string Name, string? CastType, string Literal)> defines = FrozenAbi.HeaderDefines();
        Assert.Equal(declared.Keys.Order(StringComparer.Ordinal), defines.Select(d => d.Name).Order(StringComparer.Ordinal));
        foreach ((string name, string? castType, string literal) in defines)
        {
            ulong expected = literal == "UINTPTR_MAX" ? nuint.MaxValue : FrozenAbi.ParseLiteral(literal);
            Assert.Equal(expected, declared[name].Value);
            if (castType is not null)
            {
                Assert.Equal(AbiTypeMap.ToClr(castType), declared[name].Type);
            }
            else if (name.StartsWith("SAS_PAIRING_ABI_VERSION", StringComparison.Ordinal))
            {
                Assert.Equal(typeof(uint), declared[name].Type);
            }
            else
            {
                // An uncast integer define in the status block is a sas_pairing_status_t (int32_t).
                Assert.Equal(typeof(int), declared[name].Type);
            }
        }
    }

    [Fact]
    public void TheManifestTypeTableUsesOnlyTheMappedCTypes()
    {
        IReadOnlyDictionary<string, string> manifest = FrozenAbi.ManifestTypes();
        IReadOnlyDictionary<string, string> header = FrozenAbi.HeaderScalarTypedefs();
        Assert.Equal(21, manifest.Count);
        Assert.Equal(manifest.OrderBy(p => p.Key, StringComparer.Ordinal), header.OrderBy(p => p.Key, StringComparer.Ordinal));
        string[] handles = ["sas_pairing_runtime_t", "sas_pairing_authority_t", "sas_pairing_host_t", "sas_pairing_connection_t", "sas_pairing_run_t", "sas_pairing_result_t"];
        foreach (string handle in handles)
        {
            Assert.Equal(typeof(ulong), AbiTypeMap.ToClr(handle));
        }

        Assert.Equal(typeof(int), AbiTypeMap.ToClr("sas_pairing_status_t"));
        Assert.Equal(typeof(nuint), AbiTypeMap.ToClr("sas_pairing_socket_t"));
    }
}
