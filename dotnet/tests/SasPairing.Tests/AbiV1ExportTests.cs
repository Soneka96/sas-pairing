using System.Reflection;
using System.Runtime.CompilerServices;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The 25 frozen exports: the private names list and the private function table against the manifest and
/// the header (names, order, signatures, calling convention), and the binding of exactly those 25 names.
/// </summary>
public sealed class AbiV1ExportTests
{
    internal static FieldInfo[] TableFields() =>
        [.. typeof(AbiV1FunctionTable).GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).OrderBy(f => f.MetadataToken)];

    internal static nint ReadFunctionPointer(FieldInfo field, AbiV1FunctionTable table) => field.GetValue(table) switch
    {
        nint address => address,
        Pointer pointer => ReadPointer(pointer),
        var other => throw new InvalidOperationException($"Unexpected reflected value {other?.GetType()}"),
    };

    private static unsafe nint ReadPointer(Pointer pointer) => (nint)Pointer.Unbox(pointer);

    [Fact]
    public void TheNamesListIsExactlyTheManifestExportTableInOrder()
    {
        IReadOnlyList<string> manifest = FrozenAbi.ManifestExports();
        Assert.Equal(25, manifest.Count);
        Assert.Equal(25, AbiV1Exports.Names.Count);
        Assert.Equal(manifest, AbiV1Exports.Names);
        Assert.Equal(25, AbiV1Exports.Names.Distinct().Count());
    }

    [Fact]
    public void TheNamesListIsExactlyTheHeaderDeclarationsInOrder()
    {
        Assert.Equal(FrozenAbi.HeaderFunctions().Select(f => f.Name), AbiV1Exports.Names);
    }

    [Fact]
    public void TheFunctionTableHasExactlyOneFieldPerFrozenExport()
    {
        FieldInfo[] fields = TableFields();
        Assert.Equal(25, fields.Length);
        Assert.Equal(AbiV1Exports.Names, fields.Select(f => f.Name));
        Assert.All(fields, f => Assert.True(f.IsInitOnly, $"{f.Name} must be readonly"));
        Assert.All(fields, f => Assert.True(f.IsAssembly, $"{f.Name} must be internal"));
    }

    [Fact]
    public void EverySignatureMatchesTheHeaderThroughTheMapping()
    {
        Dictionary<string, FieldInfo> fields = TableFields().ToDictionary(f => f.Name);
        IReadOnlyList<(string Name, string Return, IReadOnlyList<string> Parameters)> header = FrozenAbi.HeaderFunctions();
        Assert.Equal(25, header.Count);
        foreach ((string name, string returnType, IReadOnlyList<string> parameters) in header)
        {
            Type pointer = fields[name].FieldType;
            Assert.True(pointer.IsFunctionPointer, name);
            Assert.True(pointer.IsUnmanagedFunctionPointer, name);
            Assert.Equal(AbiTypeMap.ToClr(returnType), pointer.GetFunctionPointerReturnType());
            Assert.Equal(parameters.Select(AbiTypeMap.ToClr), pointer.GetFunctionPointerParameterTypes());
        }

        // Only the version query returns uint32_t; every other export returns sas_pairing_status_t (int).
        Assert.Equal(typeof(uint), fields["sas_pairing_abi_version"].FieldType.GetFunctionPointerReturnType());
        Assert.Equal(24, fields.Values.Count(f => f.FieldType.GetFunctionPointerReturnType() == typeof(int)));
    }

    [Fact]
    public void PointerSizedParametersAreNuintNeverUlong()
    {
        Dictionary<string, Type[]> parameters = TableFields().ToDictionary(f => f.Name, f => f.FieldType.GetFunctionPointerParameterTypes());
        Assert.Equal(typeof(nuint), parameters["sas_pairing_authority_register"][2]);
        Assert.Equal(typeof(nuint*), parameters["sas_pairing_host_attach_windows_listener"][2]);
        Assert.Equal(typeof(nuint), parameters["sas_pairing_host_drive"][3]);
        Assert.Equal(typeof(nuint*), parameters["sas_pairing_host_drive"][4]);
        Assert.Equal(typeof(nuint), parameters["sas_pairing_result_copy"][4]);
        Assert.Equal(typeof(nuint*), parameters["sas_pairing_result_copy"][5]);
        Assert.Equal(typeof(ulong), parameters["sas_pairing_runtime_destroy"][0]);
    }

    [Fact]
    public void EveryFunctionPointerUsesTheUnmanagedCdeclConvention()
    {
        foreach (FieldInfo field in TableFields())
        {
            Type[] conventions = field.GetModifiedFieldType().GetFunctionPointerCallingConventions();
            Assert.Equal([typeof(CallConvCdecl)], conventions);
        }
    }

    [Fact]
    public void BindingLooksUpExactlyTheTwentyFiveNamesOnceEachAndBindsEachToItsOwnExport()
    {
        Dictionary<string, nint> exports = [];
        nint next = 0x1000;
        foreach (string name in AbiV1Exports.Names)
        {
            exports[name] = next;
            next += 0x10;
        }

        exports["sas_pairing_future_magic"] = 0x9000; // an extra symbol in the image is never looked up
        FakeImage image = new(exports);
        AbiV1FunctionTable table = AbiV1FunctionTable.Bind(image);
        Assert.Equal(AbiV1Exports.Names, image.Lookups);
        foreach (FieldInfo field in TableFields())
        {
            Assert.Equal(exports[field.Name], ReadFunctionPointer(field, table));
        }
    }

    [Fact]
    public void BindingFailsWhenAnExportIsMissingOrNull()
    {
        FakeImage missing = FakeImage.Complete(FakeExports.Version1, "sas_pairing_run_cancel_sas");
        AbiV1BindingException error = Assert.Throws<AbiV1BindingException>(() => AbiV1FunctionTable.Bind(missing));
        Assert.Contains("sas_pairing_run_cancel_sas", error.Message, StringComparison.Ordinal);

        Dictionary<string, nint> exports = AbiV1Exports.Names.ToDictionary(n => n, _ => FakeExports.Unexpected);
        exports["sas_pairing_result_copy"] = 0;
        Assert.Throws<AbiV1BindingException>(() => AbiV1FunctionTable.Bind(new FakeImage(exports)));
    }

    [Fact]
    public void TheTableIsInternalAndSealed()
    {
        Type table = typeof(AbiV1FunctionTable);
        Assert.False(table.IsPublic);
        Assert.True(table.IsSealed);
        Assert.DoesNotContain(table.GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic), c => !c.IsPrivate);
        Assert.False(typeof(AbiV1Exports).IsPublic);
    }
}
