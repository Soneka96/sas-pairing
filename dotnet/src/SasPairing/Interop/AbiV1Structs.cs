using System.Runtime.InteropServices;

namespace SasPairing.Interop;

// The six frozen native ABI v1 records (P7-D-013 item 6, manifest section 7), with the header's type and
// field names. Every field uses the exact ABI-sized C# type of the P9-D-001 mapping (uint32_t -> uint,
// uint64_t handles -> ulong, size_t -> nuint, uint8_t arrays -> fixed byte buffers, pointers -> unmanaged
// pointers). No managed array, string, bool, char, or reference appears in a record, so each one is
// blittable and has exactly the native layout. Sizes, alignments, field order, and offsets are checked
// against the manifest and the header by the tests; the layouts are the 64-bit ones, and the loader refuses
// any process whose pointers are not 8 bytes wide before it opens a library.

/// <summary><c>sas_pairing_bytes_view_t</c>: borrowed input bytes; 16 bytes, aligned to 8.</summary>
[StructLayout(LayoutKind.Sequential)]
// UNSAFE: the record carries a raw `const uint8_t *`; it is only ever filled from memory pinned for one call.
internal unsafe struct sas_pairing_bytes_view_t
{
    public byte* data;
    public nuint len;
}

/// <summary><c>sas_pairing_bootstrap_view_t</c>: one Bootstrap configuration; 64 bytes, aligned to 8.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct sas_pairing_bootstrap_view_t
{
    public sas_pairing_bytes_view_t application_identity;
    public sas_pairing_bytes_view_t key_algorithm;
    public sas_pairing_bytes_view_t public_key;
    public sas_pairing_bytes_view_t shared_context;
}

/// <summary><c>sas_pairing_event_t</c>: one drive event; 128 bytes, aligned to 8, no padding.</summary>
[StructLayout(LayoutKind.Sequential)]
// UNSAFE: `uint8_t request_id[SAS_PAIRING_MAX_REQUEST_ID_LEN]` is an inline array, so a fixed buffer.
internal unsafe struct sas_pairing_event_t
{
    public uint kind;
    public uint step_kind;
    public uint protocol_event;
    public uint reason;
    public uint deadline_kind;
    public uint cancel_state;
    public uint cancel_reason;
    public uint flags;
    public ulong connection;
    public ulong run;
    public ulong result;
    public uint request_id_len;
    public uint reserved;
    public fixed byte request_id[64];
}

/// <summary><c>sas_pairing_result_info_t</c>: the fixed fields of one result; 56 bytes, aligned to 4.</summary>
[StructLayout(LayoutKind.Sequential)]
// UNSAFE: `uint8_t ceremony_identity[32]` is an inline array, so a fixed buffer.
internal unsafe struct sas_pairing_result_info_t
{
    public fixed byte ceremony_identity[32];
    public uint peer_role;
    public uint profile_version;
    public uint request_id_len;
    public uint peer_bootstrap_len;
    public uint shared_context_len;
    public uint profile_identifier_len;
}

/// <summary><c>sas_pairing_action_t</c>: the outcome of one trusted local action; 24 bytes, aligned to 8.</summary>
[StructLayout(LayoutKind.Sequential)]
internal struct sas_pairing_action_t
{
    public uint @event;
    public uint deadline_kind;
    public uint flags;
    public uint reserved;
    public ulong run;
}

/// <summary><c>sas_pairing_sas_presentation_t</c>: one live SAS for local comparison; 56 bytes, aligned to 4.</summary>
[StructLayout(LayoutKind.Sequential)]
// UNSAFE: the identity, decimal display, and reserved tail are inline byte arrays, so fixed buffers.
internal unsafe struct sas_pairing_sas_presentation_t
{
    public uint available;
    public uint reserved;
    public fixed byte ceremony_identity[32];
    public fixed byte @decimal[14];
    public fixed byte reserved_tail[2];
}
