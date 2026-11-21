using WebScan.Contracts;

namespace WebScan.Server.Modules.Workflows.Definitions;

/// <summary>Built-in workflows seeded on startup.</summary>
public static class StandardWorkflows
{
    public const string StandardDiscoveryKey = "standard-discovery";

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
                    new() { Field = ConditionFields.ServiceName, Operator = ConditionOperator.In, Values = ["http", "https", "http-alt", "http-proxy"] },
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
    /// DiscoverHosts → ScanPorts → DetectService → [HTTP: HttpProbe → ExecuteSignatures] [TLS: TlsProbe]
    /// → PersistObservations → ComparePreviousScan → PublishFinding.
    /// </summary>
    public static ScanWorkflowDefinition StandardDiscovery { get; } = new()
    {
        Key = StandardDiscoveryKey,
        Version = 1,
        Name = "Standard discovery",
        Description = "Host discovery, port scan, service detection, HTTP/TLS probing, approved signatures, change detection and findings.",
        Steps =
        [
            new() { Id = "discover", Operation = ScanOperation.DiscoverHosts },
            new()
            {
                Id = "ports", Operation = ScanOperation.ScanPorts, DependsOn = ["discover"],
                Input = new StepInput { FromSteps = ["discover"], Filter = KindIs(ObservationKind.HostUp) },
                Parameters = new Dictionary<string, string> { ["ports"] = "top-1000" },
            },
            new()
            {
                Id = "services", Operation = ScanOperation.DetectService, DependsOn = ["ports"],
                Input = new StepInput { FromSteps = ["ports"], Filter = KindIs(ObservationKind.PortOpen) },
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
            new() { Id = "persist", Operation = ScanOperation.PersistObservations, DependsOn = ["signatures", "tls"] },
            new() { Id = "compare", Operation = ScanOperation.ComparePreviousScan, DependsOn = ["persist"] },
            new() { Id = "publish", Operation = ScanOperation.PublishFinding, DependsOn = ["compare"] },
        ],
    };
}
