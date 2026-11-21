using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using WebScan.Contracts;

namespace WebScan.Agent.Tools;

/// <summary>
/// Verification and materialization of <see cref="SignatureBundle"/>s.
/// <para>
/// Hash format (must match the server): lowercase hex SHA-256 over the concatenation, for every item in order, of the UTF-8
/// bytes of <c>{Id}\n{Version}\n{Content}\n</c> (Version in invariant decimal, <c>\n</c> = 0x0A, no BOM). Comparison ignores hex case.
/// </para>
/// </summary>
public static partial class SignatureBundles
{
    public const string NucleiYamlFormat = "nuclei-yaml";

    public static string ComputeSha256(IReadOnlyList<SignatureContent> items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in items)
            hash.AppendData(Encoding.UTF8.GetBytes($"{item.Id}\n{item.Version.ToString(System.Globalization.CultureInfo.InvariantCulture)}\n{item.Content}\n"));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    /// <summary>Returns an error message, or null when the bundle is valid for execution.</summary>
    public static string? Validate(SignatureBundle bundle)
    {
        if (bundle.Items.Count == 0) return "Signature bundle is empty.";
        foreach (var item in bundle.Items)
        {
            if (item.Format != NucleiYamlFormat) return $"Signature '{item.Id}' has unsupported format '{item.Format}'.";
            if (!SafeId().IsMatch(item.Id)) return $"Signature id '{item.Id}' is not allowed.";
        }
        if (bundle.Items.Select(i => i.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != bundle.Items.Count) return "Signature bundle contains duplicate ids.";
        return string.Equals(ComputeSha256(bundle.Items), bundle.Sha256, StringComparison.OrdinalIgnoreCase)
            ? null
            : "Signature bundle SHA-256 mismatch.";
    }

    /// <summary>Writes every template to <c>{directory}/{id}.yaml</c>; ids are validated so they cannot escape the directory.</summary>
    public static void WriteTemplates(SignatureBundle bundle, string directory)
    {
        Directory.CreateDirectory(directory);
        foreach (var item in bundle.Items)
            File.WriteAllText(Path.Combine(directory, item.Id + ".yaml"), item.Content, new UTF8Encoding(false));
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")]
    private static partial Regex SafeId();
}
