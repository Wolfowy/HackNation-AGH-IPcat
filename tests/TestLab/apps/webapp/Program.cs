using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

// TestLab web app: HTTP on 8080, HTTPS on 8443 with a self-signed certificate generated at startup
// (so TLS probes have a certificate to report). Authorized local testing only.
var builder = WebApplication.CreateBuilder(args);
var certificate = CreateSelfSignedCertificate("testlab-webapp.local");

builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.AddServerHeader = false;
    kestrel.ListenAnyIP(8080);
    kestrel.ListenAnyIP(8443, listen => listen.UseHttps(certificate));
});

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers.Server = "Kestrel";
    context.Response.Headers["X-Powered-By"] = "ASP.NET";
    context.Response.Headers["X-TestLab-App"] = "webapp";
    await next();
});

app.MapGet("/", (HttpContext context) =>
{
    context.Response.Cookies.Append("testlab_session", Convert.ToHexString(RandomNumberGenerator.GetBytes(16)), new CookieOptions { HttpOnly = true });
    return Results.Content("""
        <!DOCTYPE html>
        <html><head><title>WebScan TestLab Web App</title></head>
        <body><h1>WebScan TestLab Web App</h1><p>ASP.NET Core sample target for authorized local testing.</p>
        <a href="/old">old link</a></body></html>
        """, "text/html; charset=utf-8");
});
app.MapGet("/old", () => Results.Redirect("/"));
app.MapGet("/health", () => "ok");

app.Run();

static X509Certificate2 CreateSelfSignedCertificate(string commonName)
{
    using var key = RSA.Create(2048);
    var request = new CertificateRequest($"CN={commonName}, O=WebScan TestLab", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    var san = new SubjectAlternativeNameBuilder();
    san.AddDnsName(commonName);
    san.AddDnsName("localhost");
    san.AddIpAddress(IPAddress.Parse("172.30.0.12"));
    request.CertificateExtensions.Add(san.Build());
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
    request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
    var now = DateTimeOffset.UtcNow;
    using var cert = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(365));
    // Re-import so the private key is usable by SslStream on Linux.
    return X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pfx), null);
}
