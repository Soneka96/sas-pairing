using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using SasPairing.Interop;
using SasPairing.Tests.Support;

namespace SasPairing.Tests;

/// <summary>
/// The six frozen records (manifest section 7) and the native type widths: exact sizes, alignments, field
/// order, offsets, field sizes, and field types, measured with <c>sizeof</c>, <c>Marshal</c>, and pointer
/// arithmetic, and compared with the manifest and the header.
/// </summary>
public sealed unsafe class AbiV1LayoutTests
{
    private static readonly Type[] Records =
    [
        typeof(sas_pairing_bytes_view_t),
        typeof(sas_pairing_bootstrap_view_t),
        typeof(sas_pairing_event_t),
        typeof(sas_pairing_result_info_t),
        typeof(sas_pairing_action_t),
        typeof(sas_pairing_sas_presentation_t),
    ];

    [Fact]
    public void TheSupportedProcessIs64Bit()
    {
        Assert.Equal(8, IntPtr.Size);
        Assert.Equal(8, sizeof(void*));
        Assert.True(Environment.Is64BitProcess);
        Assert.Equal(8, NativeAbiV1Loader.SupportedPointerSize);
    }

    [Fact]
    public void NativeTypeWidthsMatchTheMapping()
    {
        Assert.Equal(4, sizeof(int));
        Assert.Equal(4, sizeof(uint));
        Assert.Equal(8, sizeof(ulong));
        Assert.Equal(1, sizeof(byte));
        Assert.Equal(IntPtr.Size, sizeof(nuint));
        Assert.Equal(sizeof(void*), sizeof(nuint));

        // size_t and uintptr_t are pointer-sized nuint, a different type from ulong even where both are 8 bytes.
        Assert.Equal(typeof(nuint), AbiTypeMap.BaseTypes["size_t"]);
        Assert.Equal(typeof(nuint), AbiTypeMap.BaseTypes["uintptr_t"]);
        Assert.NotEqual(typeof(ulong), typeof(nuint));
    }

    [Fact]
    public void RequiredX64SizesAndAlignments()
    {
        Assert.Equal((16, 8), (sizeof(sas_pairing_bytes_view_t), AlignOf.BytesView));
        Assert.Equal((64, 8), (sizeof(sas_pairing_bootstrap_view_t), AlignOf.BootstrapView));
        Assert.Equal((128, 8), (sizeof(sas_pairing_event_t), AlignOf.Event));
        Assert.Equal((56, 4), (sizeof(sas_pairing_result_info_t), AlignOf.ResultInfo));
        Assert.Equal((24, 8), (sizeof(sas_pairing_action_t), AlignOf.Action));
        Assert.Equal((56, 4), (sizeof(sas_pairing_sas_presentation_t), AlignOf.SasPresentation));
    }

    [Fact]
    public void SizesAndAlignmentsMatchTheManifest()
    {
        IReadOnlyList<(string Record, int Size, int Align)> manifest = FrozenAbi.ManifestRecords();
        Assert.Equal(Records.Select(r => r.Name), manifest.Select(r => r.Record));
        Dictionary<string, int> alignments = new()
        {
            [nameof(sas_pairing_bytes_view_t)] = AlignOf.BytesView,
            [nameof(sas_pairing_bootstrap_view_t)] = AlignOf.BootstrapView,
            [nameof(sas_pairing_event_t)] = AlignOf.Event,
            [nameof(sas_pairing_result_info_t)] = AlignOf.ResultInfo,
            [nameof(sas_pairing_action_t)] = AlignOf.Action,
            [nameof(sas_pairing_sas_presentation_t)] = AlignOf.SasPresentation,
        };
        foreach ((string record, int size, int align) in manifest)
        {
            Type type = Records.Single(r => r.Name == record);
            Assert.True(type.IsValueType && type.IsLayoutSequential, record);
            Assert.Equal(size, Marshal.SizeOf(type));
            Assert.Equal(size, SizeOfUnmanaged(type));
            Assert.Equal(align, alignments[record]);
        }
    }

    [Fact]
    public void FieldOrderOffsetsAndSizesMatchTheManifest()
    {
        IReadOnlyList<(string Record, string Field, int Offset, int Size)> manifest = FrozenAbi.ManifestFields();
        Assert.Equal(37, manifest.Count);
        foreach (Type record in Records)
        {
            List<(string Record, string Field, int Offset, int Size)> rows = [.. manifest.Where(r => r.Record == record.Name)];
            FieldInfo[] fields = InstanceFields(record);
            Assert.Equal(rows.Select(r => r.Field), fields.Select(f => f.Name));
            int end = 0;
            foreach ((_, string field, int offset, int size) in rows)
            {
                Assert.Equal(offset, (int)Marshal.OffsetOf(record, field));
                Assert.Equal(size, FieldSize(record.GetField(field, BindingFlags.Instance | BindingFlags.Public)!));
                Assert.Equal(end, offset); // contiguous: no padding before the field
                end = offset + size;
            }

            Assert.Equal(Marshal.SizeOf(record), end); // no tail padding
        }
    }

    [Fact]
    public void CriticalOffsetsMeasuredByPointerArithmetic()
    {
        sas_pairing_event_t ev = default;
        byte* e = (byte*)&ev;
        Assert.Equal(28, (byte*)&ev.flags - e);
        Assert.Equal(32, (byte*)&ev.connection - e);
        Assert.Equal(40, (byte*)&ev.run - e);
        Assert.Equal(48, (byte*)&ev.result - e);
        Assert.Equal(56, (byte*)&ev.request_id_len - e);
        Assert.Equal(60, (byte*)&ev.reserved - e);
        Assert.Equal(64, ev.request_id - e);

        sas_pairing_result_info_t info = default;
        byte* i = (byte*)&info;
        Assert.Equal(0, info.ceremony_identity - i);
        Assert.Equal(32, (byte*)&info.peer_role - i);
        Assert.Equal(52, (byte*)&info.profile_identifier_len - i);

        sas_pairing_action_t action = default;
        byte* a = (byte*)&action;
        Assert.Equal(8, (byte*)&action.flags - a);
        Assert.Equal(16, (byte*)&action.run - a);

        sas_pairing_sas_presentation_t presentation = default;
        byte* p = (byte*)&presentation;
        Assert.Equal(8, presentation.ceremony_identity - p);
        Assert.Equal(40, presentation.@decimal - p);
        Assert.Equal(54, presentation.reserved_tail - p);

        sas_pairing_bytes_view_t view = default;
        byte* v = (byte*)&view;
        Assert.Equal(8, (byte*)&view.len - v);

        sas_pairing_bootstrap_view_t bootstrap = default;
        byte* b = (byte*)&bootstrap;
        Assert.Equal(16, (byte*)&bootstrap.key_algorithm - b);
        Assert.Equal(32, (byte*)&bootstrap.public_key - b);
        Assert.Equal(48, (byte*)&bootstrap.shared_context - b);
    }

    [Fact]
    public void FieldTypesFollowTheHeaderThroughTheMapping()
    {
        IReadOnlyDictionary<string, IReadOnlyList<(string CType, string Name, int ArrayLength)>> header = FrozenAbi.HeaderRecords();
        Assert.Equal(Records.Select(r => r.Name).Order(StringComparer.Ordinal), header.Keys.Order(StringComparer.Ordinal));
        foreach (Type record in Records)
        {
            IReadOnlyList<(string CType, string Name, int ArrayLength)> declared = header[record.Name];
            FieldInfo[] fields = InstanceFields(record);
            Assert.Equal(declared.Select(d => d.Name), fields.Select(f => f.Name));
            foreach ((string cType, string name, int arrayLength) in declared)
            {
                FieldInfo field = fields.Single(f => f.Name == name);
                if (arrayLength == 0)
                {
                    Assert.Equal(AbiTypeMap.ToClr(cType), field.FieldType);
                }
                else
                {
                    FixedBufferAttribute buffer = field.GetCustomAttribute<FixedBufferAttribute>()
                        ?? throw new InvalidOperationException($"{record.Name}.{name} must be a fixed buffer");
                    Assert.Equal(AbiTypeMap.ToClr(cType), buffer.ElementType);
                    Assert.Equal(arrayLength, buffer.Length);
                }
            }
        }
    }

    [Fact]
    public void RecordsContainNoManagedArraysStringsBooleansOrReferences()
    {
        Type[] allowed = [typeof(byte), typeof(uint), typeof(ulong), typeof(nuint), typeof(byte*), typeof(sas_pairing_bytes_view_t)];
        foreach (Type record in Records)
        {
            foreach (FieldInfo field in InstanceFields(record))
            {
                Type type = field.GetCustomAttribute<FixedBufferAttribute>()?.ElementType ?? field.FieldType;
                Assert.Contains(type, allowed);
                Assert.False(type == typeof(bool) || type == typeof(string) || type == typeof(char) || type.IsArray, $"{record.Name}.{field.Name}");
            }
        }

        Assert.False(RuntimeHelpers.IsReferenceOrContainsReferences<sas_pairing_event_t>());
        Assert.False(RuntimeHelpers.IsReferenceOrContainsReferences<sas_pairing_bootstrap_view_t>());
        Assert.False(RuntimeHelpers.IsReferenceOrContainsReferences<sas_pairing_result_info_t>());
        Assert.False(RuntimeHelpers.IsReferenceOrContainsReferences<sas_pairing_action_t>());
        Assert.False(RuntimeHelpers.IsReferenceOrContainsReferences<sas_pairing_sas_presentation_t>());
    }

    [Fact]
    public void RecordsAreInternal()
    {
        foreach (Type record in Records)
        {
            Assert.False(record.IsPublic || record.IsNestedPublic, record.Name);
        }
    }

    private static FieldInfo[] InstanceFields(Type record) =>
        [.. record.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic).OrderBy(f => (int)Marshal.OffsetOf(record, f.Name))];

    private static int FieldSize(FieldInfo field)
    {
        FixedBufferAttribute? buffer = field.GetCustomAttribute<FixedBufferAttribute>();
        return buffer is not null ? buffer.Length * Marshal.SizeOf(buffer.ElementType) : SizeOfUnmanaged(field.FieldType);
    }

    private static int SizeOfUnmanaged(Type type) =>
        type.IsPointer ? sizeof(void*) : (int)typeof(Unsafe).GetMethod(nameof(Unsafe.SizeOf))!.MakeGenericMethod(type).Invoke(null, null)!;

    // Alignment probes: the offset of a record after one leading byte is its alignment.
    [StructLayout(LayoutKind.Sequential)]
    private readonly struct BytesViewProbe(sas_pairing_bytes_view_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_bytes_view_t Value = value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct BootstrapViewProbe(sas_pairing_bootstrap_view_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_bootstrap_view_t Value = value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct EventProbe(sas_pairing_event_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_event_t Value = value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ResultInfoProbe(sas_pairing_result_info_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_result_info_t Value = value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct ActionProbe(sas_pairing_action_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_action_t Value = value;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct SasPresentationProbe(sas_pairing_sas_presentation_t value)
    {
        public readonly byte Pad = 0;
        public readonly sas_pairing_sas_presentation_t Value = value;
    }

    private static class AlignOf
    {
        internal static int BytesView => (int)Marshal.OffsetOf<BytesViewProbe>(nameof(BytesViewProbe.Value));

        internal static int BootstrapView => (int)Marshal.OffsetOf<BootstrapViewProbe>(nameof(BootstrapViewProbe.Value));

        internal static int Event => (int)Marshal.OffsetOf<EventProbe>(nameof(EventProbe.Value));

        internal static int ResultInfo => (int)Marshal.OffsetOf<ResultInfoProbe>(nameof(ResultInfoProbe.Value));

        internal static int Action => (int)Marshal.OffsetOf<ActionProbe>(nameof(ActionProbe.Value));

        internal static int SasPresentation => (int)Marshal.OffsetOf<SasPresentationProbe>(nameof(SasPresentationProbe.Value));
    }
}
