using System.Text;

namespace SasPairing.Tests.Support;

/// <summary>The production C# sources of <c>dotnet/src/SasPairing</c>, raw and with comments removed.</summary>
internal static class ProductionSource
{
    internal static string Directory => FrozenAbi.PathOf("dotnet", "src", "SasPairing");

    /// <summary>Every production <c>.cs</c> file (build output excluded), as a path relative to the project.</summary>
    internal static IReadOnlyList<string> Files()
    {
        string root = Directory;
        return
        [
            .. System.IO.Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
                .Select(path => Path.GetRelativePath(root, path).Replace('\\', '/'))
                .Where(path => !path.StartsWith("bin/", StringComparison.Ordinal) && !path.StartsWith("obj/", StringComparison.Ordinal))
                .Order(StringComparer.Ordinal),
        ];
    }

    internal static string Raw(string relative) => File.ReadAllText(Path.Combine(Directory, relative));

    /// <summary>The code of a file with every comment (line, block, and XML documentation) removed; strings kept.</summary>
    internal static string Code(string relative) => StripComments(Raw(relative));

    /// <summary>All production code, comments removed, each file prefixed by a marker line with its path.</summary>
    internal static IEnumerable<(string File, string Code)> AllCode() => Files().Select(file => (file, Code(file)));

    internal static string StripComments(string source)
    {
        StringBuilder result = new(source.Length);
        int i = 0;
        while (i < source.Length)
        {
            char c = source[i];
            char next = i + 1 < source.Length ? source[i + 1] : '\0';
            if (c == '/' && next == '/')
            {
                while (i < source.Length && source[i] != '\n')
                {
                    i++;
                }
            }
            else if (c == '/' && next == '*')
            {
                i += 2;
                while (i + 1 < source.Length && !(source[i] == '*' && source[i + 1] == '/'))
                {
                    if (source[i] == '\n')
                    {
                        result.Append('\n'); // keep line numbers aligned with the raw source
                    }

                    i++;
                }

                i += 2;
            }
            else if (c == '"' || c == '\'')
            {
                bool verbatim = i > 0 && source[i - 1] == '@';
                result.Append(c);
                i++;
                while (i < source.Length)
                {
                    char s = source[i];
                    result.Append(s);
                    i++;
                    if (!verbatim && s == '\\' && i < source.Length)
                    {
                        result.Append(source[i]);
                        i++;
                    }
                    else if (s == c)
                    {
                        break;
                    }
                }
            }
            else
            {
                result.Append(c);
                i++;
            }
        }

        return result.ToString();
    }
}
