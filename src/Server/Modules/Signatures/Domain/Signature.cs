namespace WebScan.Server.Modules.Signatures.Domain;

public enum SignatureKind
{
    /// <summary>Active detection: Nuclei YAML executed by agents.</summary>
    NucleiTemplate,

    /// <summary>Interpretation: JSON condition over observations → technology / classification tag.</summary>
    ClassificationRule,

    /// <summary>Historical: JSON rule raising the severity of matching change events.</summary>
    ChangeRule,
}

public enum SignatureStatus
{
    Draft,
    Approved,
    Retired,
}

public sealed class Signature
{
    /// <summary>Stable key (also the Nuclei template id), pattern <see cref="IdPattern"/>.</summary>
    public required string Id { get; set; }

    public required string Name { get; set; }
    public SignatureKind Kind { get; set; }
    public SignatureStatus Status { get; set; }

    /// <summary>Severity of the approved version (or of the latest one while nothing is approved).</summary>
    public string? Severity { get; set; }

    public List<string> Tags { get; set; } = [];
    public int LatestVersion { get; set; }

    /// <summary>The only version that is executable/applied.</summary>
    public int? ApprovedVersion { get; set; }

    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    public List<SignatureVersion> Versions { get; set; } = [];

    public const string IdPattern = "^[A-Za-z0-9_.-]{1,100}$";
}

/// <summary>Immutable content version. Only approval fields are written after creation.</summary>
public sealed class SignatureVersion
{
    public required string SignatureId { get; set; }
    public int Version { get; set; }
    public required string Content { get; set; }

    /// <summary>Lowercase hex SHA-256 of the UTF-8 content.</summary>
    public required string Sha256 { get; set; }

    public string? Severity { get; set; }
    public List<string> Tags { get; set; } = [];

    /// <summary>Severity above medium: approval must carry a justification note.</summary>
    public bool RequiresApprovalNote { get; set; }

    public required string CreatedBy { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public string? ApprovedBy { get; set; }
    public DateTimeOffset? ApprovedAt { get; set; }
    public string? ApprovalNote { get; set; }
}
