using Microsoft.EntityFrameworkCore;
using WebScan.Server.Modules.Signatures.Domain;
using WebScan.Server.Modules.Signatures.Validation;

namespace WebScan.Server.Modules.Signatures.Persistence;

/// <summary>Safe built-in signatures, seeded through migrations and approved by "system".</summary>
public static class BuiltInSignatures
{
    public const string SystemUser = "system";
    private static readonly DateTimeOffset SeededAt = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);

    public static readonly IReadOnlyList<(string Id, string Name, SignatureKind Kind, string Content)> All =
    [
        ("nginx-web-server", "nginx web server", SignatureKind.ClassificationRule, """
            {
              "description": "Identifies nginx from the detected service product or the HTTP Server header.",
              "when": { "any": [
                { "field": "service.product", "operator": "Contains", "values": ["nginx"] },
                { "field": "http.webServer", "operator": "Contains", "values": ["nginx"] }
              ] },
              "outcome": { "technology": { "name": "nginx", "versionField": "service.version", "category": "web-server" }, "confidence": 0.9 },
              "tags": ["tech", "web-server"]
            }
            """),
        ("apache-http-server", "Apache HTTP Server", SignatureKind.ClassificationRule, """
            {
              "description": "Identifies Apache httpd from the detected service product or the HTTP Server header.",
              "when": { "any": [
                { "field": "service.product", "operator": "Contains", "values": ["apache httpd"] },
                { "field": "http.webServer", "operator": "Equals", "values": ["Apache"] },
                { "field": "http.webServer", "operator": "StartsWith", "values": ["Apache/"] }
              ] },
              "outcome": { "technology": { "name": "Apache HTTP Server", "versionField": "service.version", "category": "web-server" }, "confidence": 0.9 },
              "tags": ["tech", "web-server"]
            }
            """),
        ("admin-panel", "Administration panel", SignatureKind.ClassificationRule, """
            {
              "description": "Classifies HTTP endpoints whose page title mentions an administration interface.",
              "when": { "all": [
                { "field": "kind", "operator": "Equals", "values": ["HttpResponse"] },
                { "field": "http.title", "operator": "Contains", "values": ["admin"] }
              ] },
              "outcome": { "classificationTag": "admin-panel", "confidence": 0.6 },
              "tags": ["classification"]
            }
            """),
        ("nginx-default-page", "Nginx default welcome page", SignatureKind.NucleiTemplate, """
            id: nginx-default-page
            info:
              name: Nginx Default Welcome Page
              author: webscan
              severity: info
              description: Detects the default nginx welcome page, indicating an unconfigured web server.
              tags: tech,nginx,misconfig
            http:
              - method: GET
                path:
                  - "{{BaseURL}}/"
                matchers-condition: and
                matchers:
                  - type: word
                    part: body
                    words:
                      - "<title>Welcome to nginx!</title>"
                  - type: status
                    status:
                      - 200
            """),
        ("sensitive-port-exposed", "Sensitive service port newly exposed", SignatureKind.ChangeRule, """
            {
              "description": "Raises newly opened remote-access / database ports to medium severity.",
              "changeTypes": ["NewPort"],
              "when": { "field": "port", "operator": "In", "values": ["21", "23", "445", "1433", "3306", "3389", "5432", "5900", "6379", "9200", "27017"] },
              "severity": "medium",
              "tags": ["exposure"]
            }
            """),
    ];

    internal static void Seed(ModelBuilder b)
    {
        foreach (var (id, name, kind, content) in All)
        {
            var validation = SignatureValidator.Validate(kind, content);
            if (!validation.Valid)
                throw new InvalidOperationException($"Built-in signature '{id}' is invalid: {string.Join("; ", validation.Errors)}");

            b.Entity<Signature>().HasData(new Signature
            {
                Id = id, Name = name, Kind = kind, Status = SignatureStatus.Approved, Severity = validation.Severity,
                Tags = [.. validation.Tags], LatestVersion = 1, ApprovedVersion = 1, CreatedAt = SeededAt, UpdatedAt = SeededAt,
            });
            b.Entity<SignatureVersion>().HasData(new SignatureVersion
            {
                SignatureId = id, Version = 1, Content = content, Sha256 = SignatureHashing.ContentSha256(content),
                Severity = validation.Severity, Tags = [.. validation.Tags], CreatedBy = SystemUser, CreatedAt = SeededAt,
                ApprovedBy = SystemUser, ApprovedAt = SeededAt, ApprovalNote = "Built-in signature",
            });
        }
    }
}
