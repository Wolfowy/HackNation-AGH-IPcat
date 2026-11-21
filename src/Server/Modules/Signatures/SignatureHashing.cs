using System.Security.Cryptography;
using System.Text;
using WebScan.Contracts;

namespace WebScan.Server.Modules.Signatures;

public static class SignatureHashing
{
    public static string ContentSha256(string content) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content)));

    /// <summary>
    /// Bundle hash shared with the agent: lowercase hex SHA-256 over UTF-8 of <c>"{id}\n{version}\n{content}\n"</c>
    /// for every item, in the given order (items are ordered by id).
    /// </summary>
    public static string BundleSha256(IEnumerable<SignatureContent> items)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var item in items)
            hash.AppendData(Encoding.UTF8.GetBytes($"{item.Id}\n{item.Version}\n{item.Content}\n"));
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
