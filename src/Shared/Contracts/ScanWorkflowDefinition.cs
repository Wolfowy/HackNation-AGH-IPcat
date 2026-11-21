namespace WebScan.Contracts;

/// <summary>
/// Declarative DAG of typed operations. Stored versioned by the server (key + version are immutable once saved).
/// Contains only approved <see cref="ScanOperation"/> values, validated parameters and typed conditions —
/// never commands, scripts or expressions that get executed.
/// </summary>
public sealed record ScanWorkflowDefinition
{
    /// <summary>Stable key, pattern <c>^[a-z0-9][a-z0-9-]{1,63}$</c>.</summary>
    public required string Key { get; init; }

    /// <summary>Assigned by the server on save (1, 2, 3...). Ignored on create.</summary>
    public int Version { get; init; }

    public required string Name { get; init; }
    public string? Description { get; init; }
    public WorkflowDefaults Defaults { get; init; } = new();
    public required IReadOnlyList<WorkflowStep> Steps { get; init; }
}

public sealed record WorkflowDefaults
{
    public int TimeoutSeconds { get; init; } = 3600;

    /// <summary>Max concurrently running jobs per step.</summary>
    public int MaxConcurrency { get; init; } = 50;

    public RetryPolicy Retry { get; init; } = new();

    /// <summary>Host batch size for agent jobs (64–1024; planner default 256).</summary>
    public int? BatchSize { get; init; }
}

public sealed record RetryPolicy
{
    public int MaxAttempts { get; init; } = 3;
    public int BackoffSeconds { get; init; } = 30;
}

public sealed record WorkflowStep
{
    /// <summary>Unique within the workflow, pattern <c>^[a-zA-Z][a-zA-Z0-9_-]{0,63}$</c>.</summary>
    public required string Id { get; init; }

    public required ScanOperation Operation { get; init; }

    /// <summary>Steps that must finish (Completed or Skipped) first. The graph must be acyclic.</summary>
    public IReadOnlyList<string> DependsOn { get; init; } = [];

    /// <summary>
    /// Where the step's targets come from. Null for the first agent step = the scan run scope (networks).
    /// </summary>
    public StepInput? Input { get; init; }

    /// <summary>Step runs only if the (filtered) input contains at least one item satisfying this condition; otherwise Skipped.</summary>
    public ConditionExpression? When { get; init; }

    /// <summary>Validated against <see cref="OperationCatalog"/> for <see cref="Operation"/>.</summary>
    public IReadOnlyDictionary<string, string> Parameters { get; init; } = new Dictionary<string, string>();

    /// <summary>Optional preferred tool id (must provide the operation's capability). Null = planner chooses.</summary>
    public string? ToolId { get; init; }

    public int? TimeoutSeconds { get; init; }
    public int? MaxConcurrency { get; init; }
    public RetryPolicy? Retry { get; init; }
    public StepFailurePolicy OnFailure { get; init; } = StepFailurePolicy.FailWorkflow;
}

public enum StepFailurePolicy
{
    FailWorkflow,
    Continue,
}

public sealed record StepInput
{
    /// <summary>Observations produced by these steps (union) form the candidate input.</summary>
    public required IReadOnlyList<string> FromSteps { get; init; }

    /// <summary>Keeps only observations matching this condition (e.g. service.name in [http, https]).</summary>
    public ConditionExpression? Filter { get; init; }
}

/// <summary>
/// Typed boolean expression over observation fields. Either a leaf (<see cref="Field"/> + <see cref="Operator"/>)
/// or a combinator (<see cref="All"/>, <see cref="Any"/>, <see cref="Not"/>). Max depth 8.
/// </summary>
public sealed record ConditionExpression
{
    /// <summary>One of <see cref="ConditionFields.All"/>.</summary>
    public string? Field { get; init; }

    public ConditionOperator? Operator { get; init; }

    /// <summary>Comparison values (strings; numeric fields are parsed).</summary>
    public IReadOnlyList<string>? Values { get; init; }

    public IReadOnlyList<ConditionExpression>? All { get; init; }
    public IReadOnlyList<ConditionExpression>? Any { get; init; }
    public ConditionExpression? Not { get; init; }
}

public enum ConditionOperator
{
    Equals,
    NotEquals,
    In,
    NotIn,
    Contains,
    StartsWith,
    GreaterThan,
    LessThan,
    Exists,
    NotExists,
}

/// <summary>Whitelisted observation fields usable in conditions (maps onto <see cref="DiscoveryObservation"/>).</summary>
public static class ConditionFields
{
    public const string Kind = "kind";
    public const string Address = "address";
    public const string Hostname = "hostname";
    public const string Port = "port";
    public const string Transport = "transport";
    public const string ToolId = "source.toolId";
    public const string HostStatus = "host.status";
    public const string PortState = "port.state";
    public const string ServiceName = "service.name";
    public const string ServiceProduct = "service.product";
    public const string ServiceVersion = "service.version";
    public const string ServiceTunnel = "service.tunnel";
    public const string HttpScheme = "http.scheme";
    public const string HttpStatusCode = "http.statusCode";
    public const string HttpTitle = "http.title";
    public const string HttpWebServer = "http.webServer";
    public const string TlsSubjectCn = "tls.subjectCommonName";
    public const string TlsIssuer = "tls.issuer";
    public const string TechnologyName = "technology.name";
    public const string TechnologyCategory = "technology.category";
    public const string SignatureId = "signature.signatureId";
    public const string SignatureSeverity = "signature.severity";
    public const string ConfidenceScore = "confidence.score";

    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal)
    {
        Kind, Address, Hostname, Port, Transport, ToolId, HostStatus, PortState, ServiceName, ServiceProduct,
        ServiceVersion, ServiceTunnel, HttpScheme, HttpStatusCode, HttpTitle, HttpWebServer, TlsSubjectCn, TlsIssuer,
        TechnologyName, TechnologyCategory, SignatureId, SignatureSeverity, ConfidenceScore,
    };
}
