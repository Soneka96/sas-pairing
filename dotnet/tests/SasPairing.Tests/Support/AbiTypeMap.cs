using SasPairing.Interop;

namespace SasPairing.Tests.Support;

/// <summary>
/// The P9-D-001 C to C# type mapping, applied to header type spellings. Independent of production code: the
/// tests derive the expected C# type of every constant, record field, parameter, and return value from the
/// header through this table and compare it with what the interop layer declares.
/// </summary>
internal static class AbiTypeMap
{
    /// <summary>The fixed mapping of the C base types used by ABI v1.</summary>
    internal static IReadOnlyDictionary<string, Type> BaseTypes { get; } = new Dictionary<string, Type>
    {
        ["int32_t"] = typeof(int),
        ["uint32_t"] = typeof(uint),
        ["uint64_t"] = typeof(ulong),
        ["uint8_t"] = typeof(byte),
        ["uintptr_t"] = typeof(nuint),
        ["size_t"] = typeof(nuint),
    };

    /// <summary>The C# type of a header type spelling such as <c>const uint8_t *</c> or <c>sas_pairing_host_t</c>.</summary>
    internal static Type ToClr(string cType)
    {
        string type = cType.Trim();
        if (type.StartsWith("const ", StringComparison.Ordinal))
        {
            type = type["const ".Length..].Trim();
        }

        if (type.EndsWith('*'))
        {
            return ToClr(type[..^1]).MakePointerType();
        }

        if (BaseTypes.TryGetValue(type, out Type? baseType))
        {
            return baseType;
        }

        IReadOnlyDictionary<string, string> typedefs = FrozenAbi.HeaderScalarTypedefs();
        if (typedefs.TryGetValue(type, out string? underlying))
        {
            return BaseTypes[underlying];
        }

        Type? record = typeof(AbiV1Constants).Assembly.GetType($"SasPairing.Interop.{type}");
        return record ?? throw new InvalidOperationException($"No C# mapping for the C type {cType}.");
    }
}
