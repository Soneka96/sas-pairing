using System.Globalization;
using System.Text.RegularExpressions;

namespace SasPairing.Tests.Support;

/// <summary>
/// The frozen native ABI v1 as the repository states it, parsed from the two authoritative sources: the
/// header <c>core/include/sas_pairing.h</c> and the manifest <c>docs/p7-native-abi/abi-v1-manifest.md</c>.
/// Test support only: production code never reads these files.
/// </summary>
internal static partial class FrozenAbi
{
    private static readonly Lazy<string> RootDirectory = new(FindRepositoryRoot);

    internal static string Root => RootDirectory.Value;

    internal static string HeaderText => File.ReadAllText(Path.Combine(Root, "core", "include", "sas_pairing.h"));

    internal static string ManifestText => File.ReadAllText(Path.Combine(Root, "docs", "p7-native-abi", "abi-v1-manifest.md"));

    internal static string PathOf(params string[] parts) => Path.Combine([Root, .. parts]);

    // ---- Manifest ----

    /// <summary>Manifest section 2: the exports in table order.</summary>
    internal static IReadOnlyList<string> ManifestExports() =>
        [.. ExportRow().Matches(ManifestSection("## 2. Exports")).Select(m => m.Groups[1].Value)];

    /// <summary>Manifest section 1: name to value.</summary>
    internal static IReadOnlyList<(string Name, string Value)> ManifestVersion() =>
        [.. NameValueRow().Matches(ManifestSection("## 1. Version")).Select(m => (m.Groups[1].Value, m.Groups[2].Value.Trim()))];

    /// <summary>Manifest section 3: the statuses.</summary>
    internal static IReadOnlyList<(string Name, string Value)> ManifestStatuses() =>
        [.. NameValueRow().Matches(ManifestSection("## 3. Status codes")).Select(m => (m.Groups[1].Value, m.Groups[2].Value.Trim()))];

    /// <summary>Manifest section 4: the integer namespace values with their C types.</summary>
    internal static IReadOnlyList<(string Name, string CType, string Value)> ManifestNamespaces() =>
        [.. NameTypeValueRow().Matches(ManifestSection("## 4. Integer namespaces")).Select(m => (m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value.Trim()))];

    /// <summary>Manifest section 5: the handle invalid values and scalar constants with their C types.</summary>
    internal static IReadOnlyList<(string Name, string CType, string Value)> ManifestScalars() =>
        [.. NameTypeValueRow().Matches(ManifestSection("## 5. Handle invalid values")).Select(m => (m.Groups[1].Value, m.Groups[2].Value, m.Groups[3].Value.Trim()))];

    /// <summary>Manifest section 6: typedef name to C type.</summary>
    internal static IReadOnlyDictionary<string, string> ManifestTypes() =>
        TypeRow().Matches(ManifestSection("## 6. Types")).ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);

    /// <summary>Manifest section 7: record sizes and alignments.</summary>
    internal static IReadOnlyList<(string Record, int Size, int Align)> ManifestRecords() =>
        [.. RecordRow().Matches(ManifestSection("## 7. Records")).Select(m => (m.Groups[1].Value, ParseInt(m.Groups[2].Value), ParseInt(m.Groups[3].Value)))];

    /// <summary>Manifest section 7: record fields in table order.</summary>
    internal static IReadOnlyList<(string Record, string Field, int Offset, int Size)> ManifestFields() =>
        [.. FieldRow().Matches(ManifestSection("## 7. Records")).Select(m => (m.Groups[1].Value, m.Groups[2].Value, ParseInt(m.Groups[3].Value), ParseInt(m.Groups[4].Value)))];

    // ---- Header ----

    /// <summary>Every <c>#define SAS_PAIRING_*</c> with a value: name to (cast type or null, literal).</summary>
    internal static IReadOnlyList<(string Name, string? CastType, string Literal)> HeaderDefines()
    {
        List<(string, string?, string)> defines = [];
        foreach (Match match in DefineLine().Matches(HeaderText))
        {
            string name = match.Groups[1].Value;
            string body = match.Groups[2].Value.Trim();
            Match cast = CastValue().Match(body);
            defines.Add(cast.Success ? (name, cast.Groups[1].Value, cast.Groups[2].Value) : (name, null, body));
        }

        return defines;
    }

    /// <summary>Every scalar <c>typedef base name;</c>: typedef name to base C type.</summary>
    internal static IReadOnlyDictionary<string, string> HeaderScalarTypedefs() =>
        ScalarTypedef().Matches(HeaderText).ToDictionary(m => m.Groups[2].Value, m => m.Groups[1].Value);

    /// <summary>Every function declaration: name to (return C type, parameter C types without names).</summary>
    internal static IReadOnlyList<(string Name, string Return, IReadOnlyList<string> Parameters)> HeaderFunctions()
    {
        List<(string, string, IReadOnlyList<string>)> functions = [];
        foreach (Match match in FunctionLine().Matches(HeaderText))
        {
            string parameters = match.Groups[3].Value.Trim();
            IReadOnlyList<string> types = parameters == "void"
                ? []
                : [.. parameters.Split(',').Select(p => ParameterType(p.Trim()))];
            functions.Add((match.Groups[2].Value, match.Groups[1].Value, types));
        }

        return functions;
    }

    /// <summary>Every record: typedef name to its fields in declaration order (C type, name, array length or 0).</summary>
    internal static IReadOnlyDictionary<string, IReadOnlyList<(string CType, string Name, int ArrayLength)>> HeaderRecords()
    {
        Dictionary<string, string> defines = HeaderDefines().ToDictionary(d => d.Name, d => d.Literal);
        Dictionary<string, IReadOnlyList<(string, string, int)>> records = [];
        foreach (Match match in RecordBlock().Matches(HeaderText))
        {
            List<(string, string, int)> fields = [];
            foreach (Match field in RecordField().Matches(match.Groups[1].Value))
            {
                string type = field.Groups[1].Value.Trim();
                string name = field.Groups[2].Value;
                string length = field.Groups[3].Value;
                int arrayLength = length.Length == 0 ? 0 : ParseInt(defines.TryGetValue(length, out string? value) ? value : length);
                fields.Add((type, name, arrayLength));
            }

            records.Add(match.Groups[2].Value, fields);
        }

        return records;
    }

    /// <summary>Parses a manifest or header integer literal (decimal, hex, <c>u</c> suffix).</summary>
    internal static ulong ParseLiteral(string literal)
    {
        string text = literal.Trim().TrimEnd('u', 'U');
        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? ulong.Parse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture)
            : ulong.Parse(text, CultureInfo.InvariantCulture);
    }

    private static int ParseInt(string text) => (int)ParseLiteral(text);

    // "const uint8_t *scope" -> "const uint8_t *"; "sas_pairing_runtime_t runtime" -> "sas_pairing_runtime_t".
    private static string ParameterType(string parameter)
    {
        Match match = ParameterParts().Match(parameter);
        if (!match.Success)
        {
            throw new FormatException($"Unrecognized parameter: {parameter}");
        }

        return match.Groups[2].Value.Length == 0 ? match.Groups[1].Value.Trim() : $"{match.Groups[1].Value.Trim()} *";
    }

    private static string ManifestSection(string heading)
    {
        string text = ManifestText.Replace("\r\n", "\n", StringComparison.Ordinal);
        int start = text.IndexOf(heading, StringComparison.Ordinal);
        if (start < 0)
        {
            throw new InvalidOperationException($"The manifest has no section {heading}.");
        }

        int end = text.IndexOf("\n## ", start + heading.Length, StringComparison.Ordinal);
        return end < 0 ? text[start..] : text[start..end];
    }

    private static string FindRepositoryRoot()
    {
        for (DirectoryInfo? directory = new(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "core", "include", "sas_pairing.h"))
                && File.Exists(Path.Combine(directory.FullName, "dotnet", "SasPairing.sln")))
            {
                return directory.FullName;
            }
        }

        throw new InvalidOperationException("The sas-pairing repository root was not found above the test output directory.");
    }

    [GeneratedRegex(@"^\| *\d+ \| `(sas_pairing_\w+)` \|", RegexOptions.Multiline)]
    private static partial Regex ExportRow();

    [GeneratedRegex(@"^\| `(SAS_PAIRING_\w+)` \| *([^|]+?) *\|$", RegexOptions.Multiline)]
    private static partial Regex NameValueRow();

    [GeneratedRegex(@"^\| `(SAS_PAIRING_\w+)` \| `(\w+)` \| *([^|]+?) *\|$", RegexOptions.Multiline)]
    private static partial Regex NameTypeValueRow();

    [GeneratedRegex(@"^\| `(sas_pairing_\w+_t)` \| `(\w+)` \|$", RegexOptions.Multiline)]
    private static partial Regex TypeRow();

    [GeneratedRegex(@"^\| `(sas_pairing_\w+_t)` \| *(\d+) \| *(\d+) \|$", RegexOptions.Multiline)]
    private static partial Regex RecordRow();

    [GeneratedRegex(@"^\| `(sas_pairing_\w+_t)` \| `(\w+)` \| *(\d+) \| *(\d+) \|$", RegexOptions.Multiline)]
    private static partial Regex FieldRow();

    [GeneratedRegex(@"^#define (SAS_PAIRING_\w+)[ \t]+(\S[^\r\n]*)$", RegexOptions.Multiline)]
    private static partial Regex DefineLine();

    [GeneratedRegex(@"^\(\((\w+)\)(\w+)\)$")]
    private static partial Regex CastValue();

    [GeneratedRegex(@"^typedef (int32_t|uint32_t|uint64_t|uintptr_t) (sas_pairing_\w+_t);", RegexOptions.Multiline)]
    private static partial Regex ScalarTypedef();

    [GeneratedRegex(@"^(sas_pairing_status_t|uint32_t) (sas_pairing_\w+)\(([^)]*)\);", RegexOptions.Multiline)]
    private static partial Regex FunctionLine();

    [GeneratedRegex(@"^((?:const )?\w+) *(\*?) *\w+$")]
    private static partial Regex ParameterParts();

    [GeneratedRegex(@"typedef struct sas_pairing_\w+ \{([^}]*)\} (sas_pairing_\w+_t);")]
    private static partial Regex RecordBlock();

    [GeneratedRegex(@"^\s*((?:const )?\w+ ?\*?) ?(\w+)(?:\[(\w+)\])?;", RegexOptions.Multiline)]
    private static partial Regex RecordField();
}
