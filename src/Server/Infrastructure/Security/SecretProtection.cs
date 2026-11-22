using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption;
using Microsoft.AspNetCore.DataProtection.AuthenticatedEncryption.ConfigurationModel;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using WebScan.Server.Infrastructure.Persistence;
using WebScan.Server.Kernel.Security;

namespace WebScan.Server.Infrastructure.Security;

internal sealed class DataProtectionSecretProtector(IDataProtectionProvider provider) : ISecretProtector
{
    private readonly IDataProtector _protector = provider.CreateProtector("WebScan.SecretProtector.v1");

    public string Protect(string plaintext) => _protector.Protect(plaintext);
    public string Unprotect(string protectedValue) => _protector.Unprotect(protectedValue);
}

public static class SecretProtectionSetup
{
    /// <summary>
    /// Data Protection with the key ring stored in <c>infra.data_protection_keys</c> (shared by every server node);
    /// the key ring is encrypted with an X509 certificate when <c>DataProtection:CertificatePath</c> is set. New keys use AES-256-GCM and
    /// roll over every <c>DataProtection:KeyLifetimeDays</c> (default 90); retired keys stay in the ring for decryption.
    /// Also backs the encrypted columns (<see cref="FieldEncryption"/>) and their startup backfill.
    /// </summary>
    public static IServiceCollection AddWebScanSecretProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var dp = services.AddDataProtection()
            .SetApplicationName("WebScan")
            .PersistKeysToDbContext<InfraDbContext>()
            .UseCryptographicAlgorithms(new AuthenticatedEncryptorConfiguration { EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM })
            .SetDefaultKeyLifetime(TimeSpan.FromDays(configuration.GetValue("DataProtection:KeyLifetimeDays", 90)));

        var certificatePath = configuration["DataProtection:CertificatePath"];
        if (!string.IsNullOrWhiteSpace(certificatePath))
        {
            var certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, configuration["DataProtection:CertificatePassword"]);
            dp.ProtectKeysWithCertificate(certificate).UnprotectKeysWithAnyCertificate(certificate);
        }

        services.AddSingleton<ISecretProtector, DataProtectionSecretProtector>();
        services.AddHostedService<FieldEncryptionBackfill>();
        return services;
    }
}
