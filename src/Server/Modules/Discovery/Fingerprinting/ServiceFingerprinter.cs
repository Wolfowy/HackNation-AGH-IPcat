using System.Globalization;
using System.Text.RegularExpressions;
using WebScan.Contracts;
using WebScan.Server.Modules.Discovery.Domain;
using WebScan.Server.Modules.Discovery.Normalization;

namespace WebScan.Server.Modules.Discovery.Fingerprinting;

internal sealed record FingerprintTechnology(string Name, string? Version, string? Category, double Score);

/// <summary>Kind of device behind a service, e.g. ("IP Camera", "Hikvision", "DS-2CD2032").</summary>
internal sealed record DeviceClassification(string Type, string? Vendor, string? Product);

internal sealed class FingerprintResult
{
    public List<FingerprintTechnology> Technologies { get; } = [];
    public DeviceClassification? Device { get; set; }
    public string? OsGuess { get; set; }
    public List<ServiceArtifact> Artifacts { get; } = [];
    public bool IsEmpty => Technologies.Count == 0 && Device is null && OsGuess is null && Artifacts.Count == 0;
}

/// <summary>
/// Turns already collected HTTP responses, banners and certificates into technologies (method "recog"), a device classification
/// (IoT detection) and interesting artifacts, using <see cref="RecogDatabase"/> and <see cref="HttpArtifacts"/>.
/// </summary>
internal static partial class ServiceFingerprinter
{
    public static FingerprintResult Http(HttpDetails http, string address, RecogDatabase? recog = null)
    {
        recog ??= RecogDatabase.Default;
        var result = new FingerprintResult();
        Apply(result, recog.Match(RecogDatabase.HttpServer, HttpArtifacts.Header(http, "server") ?? http.WebServer));
        Apply(result, recog.Match(RecogDatabase.HtmlTitle, http.Title));
        Apply(result, recog.Match(RecogDatabase.HttpWwwAuth, HttpArtifacts.Header(http, "www-authenticate")));
        // Values are masked, so only name-based cookie fingerprints can match.
        foreach (var cookie in http.Cookies) Apply(result, recog.Match(RecogDatabase.HttpCookie, cookie.Name + "="));
        if (Apply(result, recog.Match(RecogDatabase.FaviconMd5, http.FaviconMd5)) is { } favicon)
            HttpArtifacts.Add(result.Artifacts, "favicon", "favicon", http.FaviconMd5, $"Favicon of {Short(favicon.Description)}", ["tech-hint"], "info");
        result.Artifacts.AddRange(HttpArtifacts.Detect(http, address));
        return result;
    }

    /// <summary>SSH and FTP banners (recog expects them without the protocol prefix / reply code).</summary>
    public static FingerprintResult Banner(ServiceDetails service, RecogDatabase? recog = null)
    {
        recog ??= RecogDatabase.Default;
        var result = new FingerprintResult();
        var line = service.Banner?.Split('\n')[0].Trim();
        if (string.IsNullOrEmpty(line)) return result;
        if (service.Name == "ssh") Apply(result, recog.Match(RecogDatabase.SshBanner, SshPrefix().Replace(line, "")));
        else if (service.Name == "ftp") Apply(result, recog.Match(RecogDatabase.FtpBanner, FtpPrefix().Replace(line, "")));
        return result;
    }

    /// <summary>Default device/vendor certificates; generic CA matches (certainty 0) add nothing.</summary>
    public static FingerprintResult Tls(TlsDetails tls, RecogDatabase? recog = null)
    {
        recog ??= RecogDatabase.Default;
        var result = new FingerprintResult();
        foreach (var (key, name, dn) in new[] { (RecogDatabase.X509Subject, "subject", tls.SubjectDn), (RecogDatabase.X509Issuer, "issuer", tls.Issuer) })
        {
            var before = result.Technologies.Count;
            if (Apply(result, recog.Match(key, RecogDn(dn))) is { } match && (result.Technologies.Count > before || result.Device is not null))
                HttpArtifacts.Add(result.Artifacts, "cert", name, dn, $"Certificate {name} matches {Short(match.Description)}", ["tech-hint"], "info");
        }
        return result;
    }

    private static RecogMatch? Apply(FingerprintResult result, RecogMatch? match)
    {
        if (match is null) return null;
        AddTechnology(result, match, "service", null);
        AddTechnology(result, match, "os", "os");
        AddTechnology(result, match, "hw", "device");
        if (Certainty(match, "os") > 0 && Name(match, "os") is { } os) result.OsGuess ??= os;
        var type = Certainty(match, "hw") > 0 ? match["hw.device"] : null;
        type ??= Certainty(match, "os") > 0 ? match["os.device"] : null;
        if (result.Device is null && type is not null and not "General")
            result.Device = new DeviceClassification(type, match["hw.vendor"] ?? match["os.vendor"], match["hw.product"]);
        return match;
    }

    private static void AddTechnology(FingerprintResult result, RecogMatch match, string prefix, string? category)
    {
        var score = Certainty(match, prefix);
        if (score <= 0 || Name(match, prefix) is not { } name) return;
        result.Technologies.Add(new FingerprintTechnology(name, match[$"{prefix}.version"], category, score));
    }

    /// <summary>"{vendor} {product}" unless the product already names the vendor (Apache + HTTPD → "Apache HTTPD", nginx + nginx → "nginx").</summary>
    private static string? Name(RecogMatch match, string prefix)
    {
        if (match[$"{prefix}.product"] is not { } product) return null;
        var vendor = match[$"{prefix}.vendor"];
        return vendor is null || product.Contains(vendor, StringComparison.OrdinalIgnoreCase) ? product : $"{vendor} {product}";
    }

    /// <summary>The fingerprint's own <c>*.certainty</c> param, otherwise the base score of the "recog" method.</summary>
    private static double Certainty(RecogMatch match, string prefix) =>
        double.TryParse(match[$"{prefix}.certainty"], NumberStyles.Float, CultureInfo.InvariantCulture, out var c)
            ? Math.Clamp(c, 0, 1)
            : ConfidenceModel.BaseScore(ConfidenceModel.Recog);

    /// <summary>Recog DNs are comma-separated without blanks ("CN=x,O=y"); httpx/tlsx print "CN=x, O=y".</summary>
    private static string? RecogDn(string? dn) => dn is null ? null : DnSeparator().Replace(dn.Trim(), ",");

    private static string Short(string description)
    {
        var cut = description.IndexOf(" http", StringComparison.Ordinal);
        var s = cut > 0 ? description[..cut] : description;
        return s.Length > 100 ? s[..100] : s;
    }

    [GeneratedRegex(@"^SSH-\d+(\.\d+)?-")]
    private static partial Regex SshPrefix();

    [GeneratedRegex(@"^\d{3}[- ]")]
    private static partial Regex FtpPrefix();

    [GeneratedRegex(@",\s+(?=[A-Za-z][A-Za-z0-9.]*=)")]
    private static partial Regex DnSeparator();
}
