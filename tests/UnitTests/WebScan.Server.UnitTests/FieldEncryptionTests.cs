using System.Buffers.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Persistence;

namespace WebScan.Server.UnitTests;

public sealed class FieldEncryptionTests
{
    private readonly FieldEncryptor _encryptor = new(new EphemeralDataProtectionProvider());

    [Fact]
    public void Round_trip_uses_a_versioned_envelope_and_a_fresh_nonce_per_value()
    {
        var a = _encryptor.Encrypt("Server: Apache/2.4.1 (internal-build)");
        var b = _encryptor.Encrypt("Server: Apache/2.4.1 (internal-build)");

        Assert.StartsWith(FieldEncryptor.Prefix, a);
        Assert.DoesNotContain("Apache", a);
        Assert.NotEqual(a, b);
        Assert.Equal("Server: Apache/2.4.1 (internal-build)", _encryptor.Decrypt(a));
        Assert.Equal("", _encryptor.Decrypt(_encryptor.Encrypt("")));
    }

    [Fact]
    public void Tampered_ciphertext_and_foreign_keys_are_rejected()
    {
        var stored = _encryptor.Encrypt("owner: alice");
        var flipped = stored[..^3] + (stored[^3] == 'A' ? 'B' : 'A') + stored[^2..];

        Assert.ThrowsAny<CryptographicException>(() => _encryptor.Decrypt(flipped));
        Assert.ThrowsAny<CryptographicException>(() => new FieldEncryptor(new EphemeralDataProtectionProvider()).Decrypt(stored));
    }

    [Fact]
    public void Legacy_plaintext_without_the_prefix_is_returned_unchanged()
    {
        Assert.False(FieldEncryptor.IsEncrypted("{\"kind\":\"Service\"}"));
        Assert.Equal("{\"kind\":\"Service\"}", _encryptor.Decrypt("{\"kind\":\"Service\"}"));
    }

    [Fact]
    public void After_key_rotation_new_values_use_the_new_key_and_old_values_still_decrypt()
    {
        var directory = Directory.CreateTempSubdirectory("webscan-dp-");
        try
        {
            ServiceProvider Node() => new ServiceCollection().AddDataProtection().PersistKeysToFileSystem(directory).Services.BuildServiceProvider();
            using var before = Node();
            var old = new FieldEncryptor(before.GetRequiredService<IDataProtectionProvider>()).Encrypt("before rotation");
            var now = DateTimeOffset.UtcNow;
            before.GetRequiredService<IKeyManager>().CreateNewKey(now, now.AddDays(90));

            using var after = Node(); // e.g. after a restart: the key ring is re-read
            var encryptor = new FieldEncryptor(after.GetRequiredService<IDataProtectionProvider>());
            var fresh = encryptor.Encrypt("after rotation");

            Assert.NotEqual(KeyId(old), KeyId(fresh));
            Assert.Equal("before rotation", encryptor.Decrypt(old));
            Assert.Equal("after rotation", encryptor.Decrypt(fresh));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    // Data Protection payload: 4-byte magic header, then the 16-byte id of the key that encrypted it.
    private static Guid KeyId(string stored) => new(Base64Url.DecodeFromChars(stored[FieldEncryptor.Prefix.Length..])[4..20]);
}
