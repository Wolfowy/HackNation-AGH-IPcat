using WebScan.Contracts;

namespace WebScan.Server.Modules.Workflows.Definitions;

/// <summary>Built-in workflows seeded on startup.</summary>
public static class StandardWorkflows
{
    public const string StandardDiscoveryKey = "standard-discovery";
    public const string FullDiscoveryKey = "full-discovery";

    /// <summary>
    /// Ports of the first sweep: nmap's top 1000 plus common service ports outside it (message brokers, databases, caches,
    /// container/orchestration and admin APIs), so hosts that only run such services are not dropped by the sweep.
    /// </summary>
    public static readonly string SweepPorts = PortSet.FromPorts(NmapTopPorts.Top(1000)!.Ranges
        .SelectMany(r => Enumerable.Range(r.From, r.To - r.From + 1))
        .Concat([
            1433, 1521, 2049, 2375, 2376, 2379, 3000, 3306, 4369, 5000, 5432, 5601, 5672, 5984, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8086,
            8088, 8443, 8787, 8888, 9000, 9042, 9090, 9092, 9200, 9300, 9443, 10250, 11211, 15672, 25672, 27017, 50000,
        ])).ToString();

    private static ConditionExpression KindIs(ObservationKind kind) =>
        new() { Field = ConditionFields.Kind, Operator = ConditionOperator.Equals, Values = [kind.ToString()] };

    private static readonly ConditionExpression IsHttpService = new()
    {
        All =
        [
            KindIs(ObservationKind.Service),
            new()
            {
                Any =
                [
                    // Unidentified services (no -sV match, tcpwrapped) are probed too: many web apps (Gitea, httpbin, admin
                    // consoles on odd ports) are not recognized by nmap, and an HTTP probe of a non-HTTP port just fails.
                    new() { Field = ConditionFields.ServiceName, Operator = ConditionOperator.In, Values = ["http", "https", "http-alt", "http-proxy", "unknown", "tcpwrapped"] },
                    new() { Field = ConditionFields.ServiceTunnel, Operator = ConditionOperator.Equals, Values = ["ssl"] },
                ],
            },
        ],
    };

    private static readonly ConditionExpression IsTlsService = new()
    {
        All =
        [
            KindIs(ObservationKind.Service),
            new()
            {
                Any =
                [
                    new() { Field = ConditionFields.ServiceTunnel, Operator = ConditionOperator.Equals, Values = ["ssl"] },
                    new() { Field = ConditionFields.Port, Operator = ConditionOperator.In, Values = ["443", "8443"] },
                ],
            },
        ],
    };

    /// <summary>
    /// ScanPorts sweep (masscan) → ScanPorts on the hosts with open ports → DetectService → [HTTP: HttpProbe → ExecuteSignatures] [TLS: TlsProbe]
    /// → RecheckMissing → PersistObservations → ComparePreviousScan → PublishFinding.
    /// </summary>
    public static ScanWorkflowDefinition StandardDiscovery { get; } = new()
    {
        Key = StandardDiscoveryKey,
        Version = 1,
        Name = "Standard discovery",
        Description = "Fast masscan sweep of the scope, thorough port scan and service detection of the hosts it found, HTTP/TLS probing, approved signatures, re-check of missing targets, change detection and findings.",
        Steps =
        [
            // Fast first sweep of the whole scope (masscan where an agent can run it, else naabu/nmap): only the hosts with
            // something open go on to the thorough steps.
            new()
            {
                Id = "sweep", Operation = ScanOperation.ScanPorts, ToolId = "masscan",
                Parameters = new Dictionary<string, string> { ["ports"] = SweepPorts, ["rate"] = "10000" },
            },
            new()
            {
                Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["sweep"],
                Input = new StepInput { FromSteps = ["sweep"], Filter = KindIs(ObservationKind.PortOpen) },
                Parameters = new Dictionary<string, string> { ["ports"] = "top-1000" },
            },
            new()
            {
                Id = "services", Operation = ScanOperation.DetectService, DependsOn = ["ports"],
                Input = new StepInput { FromSteps = ["sweep", "ports"], Filter = KindIs(ObservationKind.PortOpen) },
            },
            new()
            {
                Id = "http", Operation = ScanOperation.HttpProbe, DependsOn = ["services"], OnFailure = StepFailurePolicy.Continue,
                Input = new StepInput { FromSteps = ["services"], Filter = IsHttpService }, When = IsHttpService,
            },
            new()
            {
                Id = "signatures", Operation = ScanOperation.ExecuteSignatures, DependsOn = ["http"], OnFailure = StepFailurePolicy.Continue,
                Input = new StepInput { FromSteps = ["http"], Filter = KindIs(ObservationKind.HttpResponse) },
            },
            new()
            {
                Id = "tls", Operation = ScanOperation.TlsProbe, DependsOn = ["services"], OnFailure = StepFailurePolicy.Continue,
                Input = new StepInput { FromSteps = ["services"], Filter = IsTlsService }, When = IsTlsService,
            },
            new() { Id = "recheck", Operation = ScanOperation.RecheckMissing, DependsOn = ["signatures", "tls"], OnFailure = StepFailurePolicy.Continue },
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["recheck"] },
            new() { Id = "compare", Operation = ScanOperation.ComparePreviousScan, DependsOn = ["persist"] },
            new() { Id = "publish", Operation = ScanOperation.PublishFinding, DependsOn = ["compare"] },
        ],
    };

    /// <summary>Standard discovery with a full TCP port range (1-65535) on the hosts found alive.</summary>
    public static ScanWorkflowDefinition FullDiscovery { get; } = StandardDiscovery with
    {
        Key = FullDiscoveryKey,
        Name = "Full discovery (all ports)",
        Description = "Standard discovery over all 65535 TCP ports of the live hosts: finds services on non-standard ports at the cost of a longer port scan.",
        Steps = [.. StandardDiscovery.Steps.Select(s => s.Id == "ports" ? s with { Parameters = new Dictionary<string, string> { ["ports"] = "1-65535" } } : s)],
    };

    public static IReadOnlyList<ScanWorkflowDefinition> All { get; } = [StandardDiscovery, FullDiscovery];
}
