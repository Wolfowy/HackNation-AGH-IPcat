namespace WebScan.Agent;

/// <summary>Agent configuration, section <c>Agent</c>. See <c>src/Agent/Worker/appsettings.json</c> for documentation of every key.</summary>
public sealed class AgentOptions
{
    public const string Section = "Agent";

    public string ServerUrl { get; set; } = "https://localhost:5443";

    /// <summary>Stable agent id; default is the sanitized hostname. Credentials persisted on disk take precedence.</summary>
    public string? AgentId { get; set; }

    /// <summary>One-time enrollment token used on first start when no credentials are stored.</summary>
    public string? EnrollmentToken { get; set; }

    /// <summary>SQLite buffer and credential file location. Default: &lt;LocalApplicationData&gt;/webscan-agent.</summary>
    public string? DataDirectory { get; set; }

    public int MaxConcurrentJobs { get; set; } = 4;

    /// <summary>Default = <see cref="MaxConcurrentJobs"/>.</summary>
    public int? MaxConcurrentJobsPerInterface { get; set; }

    public int MaxRatePerSecond { get; set; } = 2000;
    public List<string> DeclaredZones { get; set; } = [];

    /// <summary>
    /// Whether the scanning tools can use raw sockets (SYN scans, ICMP/ARP discovery). Null = detect: root, CAP_NET_RAW, or
    /// <c>NMAP_PRIVILEGED</c> set (the container image grants the tools file capabilities and sets it).
    /// </summary>
    public bool? RawSockets { get; set; }

    /// <summary>Directories with tool manifests (*.json). Default: &lt;app&gt;/tools.d.</summary>
    public List<string> ToolManifestPaths { get; set; } = [];

    /// <summary>Plugin assemblies (*.dll files or directories). Installed locally by the operator, never downloaded.</summary>
    public List<string> PluginPaths { get; set; } = [];

    /// <summary>When non-empty, only plugin assemblies whose SHA-256 (hex) is listed are loaded.</summary>
    public List<string> TrustedPluginSha256 { get; set; } = [];

    /// <summary>Registers the synthetic "fake" adapter (tests, load tests, E2E). Never enable in production.</summary>
    public bool EnableFakeTools { get; set; }

    /// <summary>Overrides the heartbeat interval sent by the server.</summary>
    public int? HeartbeatIntervalSeconds { get; set; }

    public int ResultBatchMaxObservations { get; set; } = 500;
    public int ResultBatchFlushSeconds { get; set; } = 5;

    /// <summary>Time allowed on shutdown for flushing buffered results.</summary>
    public int ShutdownFlushSeconds { get; set; } = 10;

    /// <summary>Initial delay of the loops' exponential backoff (max 60 s) while the server is unreachable.</summary>
    public double ErrorBackoffSeconds { get; set; } = 1;

    /// <summary>Quick retries of transient HTTP failures (5xx, 408, 429, network errors) inside one call.</summary>
    public int HttpRetryAttempts { get; set; } = 3;

    public int HttpRetryBaseDelayMs { get; set; } = 500;

    public int HttpTimeoutSeconds { get; set; } = 60;

    public InterfaceFilterOptions Interfaces { get; set; } = new();

    /// <summary>Replaces detected interfaces (simulated agents, multi-perspective demos).</summary>
    public List<StaticInterfaceOptions> StaticInterfaces { get; set; } = [];

    /// <summary>Replaces detected routes.</summary>
    public List<StaticRouteOptions> StaticRoutes { get; set; } = [];

    public FakeToolOptions FakeTools { get; set; } = new();
}

public sealed class InterfaceFilterOptions
{
    /// <summary>Interface names to report (empty = all). Exact names.</summary>
    public List<string> Include { get; set; } = [];

    public List<string> Exclude { get; set; } = [];
}

public sealed class StaticInterfaceOptions
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string? MacAddress { get; set; }
    public bool IsUp { get; set; } = true;
    public List<string> Addresses { get; set; } = [];
    public long? SpeedMbps { get; set; }
}

public sealed class StaticRouteOptions
{
    public string Destination { get; set; } = "";
    public string? Gateway { get; set; }
    public string InterfaceName { get; set; } = "";
    public int Metric { get; set; }
}

/// <summary>
/// Section <c>Agent:FakeTools</c>: deterministic overrides for the synthetic scanner, read through IOptionsMonitor on every job,
/// so tests can introduce a change between two scans without restarting the agent.
/// </summary>
public sealed class FakeToolOptions
{
    /// <summary>Share of addresses reported up (0..1), derived deterministically from a hash of the address.</summary>
    public double AliveRatio { get; set; } = 0.6;

    public int DelayPerTargetMs { get; set; }

    /// <summary>Address → ports reported open in addition to the synthetic ones (if within the requested port spec).
    /// IPv4 keys only: ':' is the configuration key separator.</summary>
    public Dictionary<string, List<int>> ExtraOpenPorts { get; set; } = [];

    /// <summary>Address → ports never reported open (IPv4 keys only).</summary>
    public Dictionary<string, List<int>> ClosedPorts { get; set; } = [];

    /// <summary>Addresses always reported down (no ports, services, ...).</summary>
    public List<string> DownHosts { get; set; } = [];

    /// <summary>Services reported by service detection for specific endpoints. A list (not an "addr:port" map) because ':' separates configuration keys.</summary>
    public List<FakeServiceOverride> ServiceOverrides { get; set; } = [];
}

public sealed class FakeServiceOverride
{
    public string Address { get; set; } = "";
    public int Port { get; set; }
    public string Name { get; set; } = "unknown";
    public string? Product { get; set; }
    public string? Version { get; set; }
}
