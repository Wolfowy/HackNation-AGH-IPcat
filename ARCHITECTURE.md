# WebScan — Distributed Network Discovery & Attack Surface Intelligence

Architecture & coordination document. **Every development agent reads this before writing code.**
Contracts in `src/Shared/Contracts` and ports in `src/Server/Kernel` are the stable interface between work streams.

## 1. Components

```
                ┌──────────────────────── Central Server (ASP.NET Core, .NET 10, modular monolith) ─────────────────────┐
 Admin UI  ───► │  Api (composition root)                                                                              │
 (React)   ◄─── │   Identity │ Agents │ Networks │ Scanning │ Scheduling │ Workflows │ Signatures │ Discovery │ Analytics │ Integrations
  SignalR       │   Kernel (ports, security constants, IpRangeSet)   Infrastructure (persistence, audit, secrets, messaging, OTel) │
                └───────┬───────────────────────┬──────────────────────────────┬───────────────────────────────────────┘
                        │ EF Core (schema/module)│ Wolverine (RabbitMQ / local)  │ HTTPS (agent-initiated only)
                   PostgreSQL               RabbitMQ                      ┌────┴─────┐  ┌──────────┐
                                                                          │ Agent #1 │  │ Agent #N │  .NET Worker, tools via CLI
                                                                          └──────────┘  └──────────┘  (nmap, naabu, httpx, nuclei, any manifest tool)
```

* Agents **always initiate** connections (NAT/firewall friendly): register → heartbeat → claim jobs → stream results.
* Agents never touch PostgreSQL. Local SQLite is only a result buffer.
* Observations are stored in PostgreSQL, never only in telemetry.

## 2. Repository layout and ownership (parallel work streams)

| Path | Owner stream |
|---|---|
| `src/Shared/Contracts` | Coordinator (stable; changes only by coordinator) |
| `src/Server/Kernel` | Coordinator. Streams may **add new files** (never edit existing ones without coordinator approval) |
| `src/Server/Api`, `src/Server/Infrastructure`, `Modules/Identity`, `Modules/Agents`, `Modules/Networks`, `deploy/` | **A — Core Backend & Infrastructure** |
| `src/Agent/**`, `tests/TestLab/**`, `tests/UnitTests/WebScan.Agent.UnitTests` | **B — Scanner Agent & Execution** |
| `Modules/Scanning`, `Modules/Scheduling`, `Modules/Workflows`, `tests/UnitTests/WebScan.Scheduling.UnitTests` | **C — Scheduler & Workflow Engine** |
| `Modules/Discovery`, `Modules/Analytics`, `Modules/Signatures`, `Modules/Integrations`, `tests/UnitTests/WebScan.Discovery.UnitTests` | **D — Discovery Intelligence & Analysis** |
| `src/Frontend/**`, `tests/E2ETests/playwright/**` | **E — Frontend & Integration Testing** |
| `tests/UnitTests/WebScan.Server.UnitTests` | A |
| `tests/IntegrationTests`, `tests/E2ETests/WebScan.E2ETests` | Coordinator (after merge) |

Rules: do not edit files owned by another stream; `Directory.Packages.props` holds every package version (add a line only if
unavoidable and mention it in your report); never add paid-license libraries (no FluentAssertions ≥ 8, no MediatR ≥ 13, etc.).
`Program.cs` is owned by A; each module exposes `AddXModule(IServiceCollection, IConfiguration)` and `MapXEndpoints(IEndpointRouteBuilder)`
which are already wired.

## 3. Contracts (`src/Shared/Contracts`)

| Contract | File | Purpose |
|---|---|---|
| `ScanJob` (+ `JobAssignment`, `JobLease`, `JobTargets`, `ToolSelection`, `SignatureBundle`) | `ScanJob.cs` | unit of work for one agent/tool/perspective/batch |
| `AgentRegistration` (+ heartbeat, credentials) | `AgentRegistration.cs` | agent capabilities, interfaces, routes, tools, limits |
| `DiscoveryObservation` | `DiscoveryObservation.cs` | normalized, tool-independent result |
| `ScanWorkflowDefinition` | `ScanWorkflowDefinition.cs` | DAG of typed operations + typed conditions |
| `ScanResultBatch` (+ job heartbeat/complete/fail/claim DTOs, `AgentApiRoutes`) | `ScanResultBatch.cs` | idempotent result upload |
| `ScanExecutionEvent` (+ `ScanHub`) | `ScanExecutionEvent.cs` | execution state events (DB + SignalR) |
| `OperationCatalog`, `ToolCapabilities`, `ParameterValidator` | `Operations.cs`, `ParameterValidator.cs` | operation semantics & parameter schemas, shared validation |
| `SensitiveDataMasker`, `ContractJson` | | masking secrets; wire JSON options (camelCase, string enums) |

Wire format everywhere (agent API and UI API): `ContractJson.Configure(options)` — camelCase, enums as strings, nulls omitted.
Times are `DateTimeOffset` UTC. Use `TimeProvider` (injectable) instead of `DateTime.UtcNow` in logic that tests must control.

## 4. Persistence

* PostgreSQL, EF Core 10, **one DbContext per module, one schema per module**: `identity`, `agents`, `networks`, `scanning`,
  `scheduling`, `workflows`, `signatures`, `discovery`, `analytics`, `integrations`; Infrastructure uses `infra` (audit log,
  Data Protection keys, settings); Wolverine uses `wolverine`.
* Register with `services.AddModuleDbContext<TContext>("schema")` (Infrastructure); call `modelBuilder.HasDefaultSchema(schema)`.
  Each module ships `XDesignTimeFactory : ModuleDesignTimeFactory<XDbContext>` and its own migrations in `Persistence/Migrations`:
  `dotnet ef migrations add Initial --project src/Server/Modules/X --startup-project src/Server/Modules/X --context XDbContext -o Persistence/Migrations`.
* Server applies all module migrations on startup (`Database:MigrateOnStartup`, default true).
* Cross-module references are ids only (no cross-schema FKs). Cross-module calls go through Kernel ports (`src/Server/Kernel/Ports`).
* Integration tests use Testcontainers PostgreSQL (`postgres:17-alpine`). Unit tests use fakes for ports.

## 5. Messaging (Wolverine)

* Wolverine with RabbitMQ transport when `RabbitMq:ConnectionString` is set; otherwise local durable queues (tests).
  Message persistence / outbox in PostgreSQL (`wolverine` schema). Handlers are discovered in `ModuleAssemblies.All`.
* Cross-module messages: `src/Server/Kernel/Messaging/Messages.cs`
  (`ScanResultBatchReceived`, `ScanJobFinished`, `AgentWentOffline`, `ScanRunFinished`, `AssetChangesDetected`).
* Store + publish atomically with Wolverine's EF Core outbox (`IDbContextOutbox<TContext>`) where a lost message would lose data
  (result batches). Handlers must be idempotent.

## 6. Security

* **Users**: JWT bearer (`AuthSchemes.User`), local user store, `PasswordHasher<T>`. Default admin is seeded from
  `Bootstrap:AdminUserName` / `Bootstrap:AdminPassword` (required in non-Development environments; no hardcoded password).
* **RBAC** (`Kernel/Security`): roles `Administrator ⊃ Manager ⊃ Editor ⊃ Viewer`; policies `CanRead`, `CanEdit` (Editor+),
  `CanManage` (Manager+), `AdminOnly`, `Agent`. Every endpoint declares a policy; default policy = deny.
* **Agents**: bootstrap with an admin-created, hashed, expiring, use-limited **enrollment token** (`X-Enrollment-Token`) →
  server returns a 256-bit agent secret (stored as SHA-256). Then `Authorization: Agent {agentId}:{secret}` (`AuthSchemes.Agent`).
  Rotation: `POST /api/agents/credentials/rotate` (old secret valid for a grace period); heartbeat may request rotation.
  Disabled/Blocked agents fail authentication immediately.
* HTTPS everywhere (Kestrel cert from config; dev script generates a CA + server cert; agent can pin the CA via `Server:CaCertificatePath`).
* **Scope**: global scope policy (allowed CIDRs/domains + global exclusions, AdminOnly) ⊇ networks ⊇ jobs. Networks outside the
  policy are rejected; the planner re-checks; the agent re-checks every target against `ScanJob.AuthorizedScope`.
* **No arbitrary commands**: workflows contain only `ScanOperation` values and schema-validated string parameters
  (`ParameterValidator`, unknown parameters rejected). Agents build argv (no shell) from local manifests.
* Audit log (`IAuditLog`) for every mutating admin action. Secrets at rest encrypted with `ISecretProtector` (Data Protection, keys in DB,
  key ring protected by a certificate when configured). Cookie values/tokens masked with `SensitiveDataMasker` on agent **and** server.

## 7. Extensible scanning tools (no hardcoded tool list)

Tools are **data, not code paths**. Nothing on the server switches on tool names.

**Agent side** (stream B):
* Tool manifests in `tools.d/*.json` (paths from `Agent:ToolManifestPaths`). Shipped manifests: `nmap`, `naabu`, `httpx`, `nuclei`,
  `fake` (disabled unless `Agent:EnableFakeTools=true`). A manifest declares: `id`, `executable`, version detection, **capabilities**,
  `adapter` (`"manifest"` = generic argv-template runner, or a plugin adapter id), `parser` id, input/output mode, an **argv template**
  with whitelisted placeholders (`{input}`, `{output}`, `{rate}`, `{timeout}`, `{parallelism}`, `{interface}`, `{templatesDir}`),
  per-parameter argument mappings for parameters from `OperationCatalog`, concurrency and timeout.
* Parsers are registered by id (`nmap-xml`, `naabu-jsonl`, `httpx-jsonl`, `nuclei-jsonl`, `generic-jsonl` with a declarative field
  mapping). Adapters/parsers can also come from plugin assemblies in `Agent:PluginPaths` (built against `WebScan.Agent.Tools.Abstractions`;
  optional SHA-256 allowlist). Plugins/manifests are installed locally by the agent operator — **never pushed by the server**.
* Agent registers only tools whose executable was found and version detected; the job's `ToolSelection.ToolId` picks the tool,
  falling back to any local tool with the required capability.
* Adding a tool = drop a manifest (+ optionally a parser plugin). No server change, no agent recompilation for JSONL tools.

**Server side** (streams A + C):
* Tool catalog (Agents module): every reported tool id is recorded; new ids are **unapproved** until an administrator approves them
  (`Tools:AutoApprove` config list may pre-approve, defaults `nmap,naabu,httpx,nuclei`). `IAgentDirectory` exposes only approved tools.
* Operation → capability mapping: defaults from `OperationCatalog`, overridable in config `Planner:OperationCapabilities`.
  Tool preference per capability: `Planner:ToolPreference:{capability}` (ordered ids). A workflow step may pin `toolId`.
* `GET /api/operations` exposes catalog + effective mapping for the UI.

## 8. Task planner, jobs and leases (stream C)

* Scope resolution: `INetworkScopeService.ResolveAsync` → `IpRangeSet` (Kernel) union of includes minus network + global exclusions;
  hostnames kept as separate host entries. IPv6 segments larger than `Planner:MaxIpv6SegmentAddresses` are rejected.
* Batching: `IpRangeSet.SplitIntoBatches(batchSize)` (default 256, configurable 64–1024, rounded to power of two) — deterministic,
  non-overlapping, CIDR-aligned.
* Eligibility: agent Active + online + approved tool with capability + authorized zone (and network if restricted) + reachability
  (interface subnet or route covering the batch; default route counts only if `Planner:AllowDefaultRoute`). Perspective = (agent, interface).
* Tool parameters: a job carries the step's explicitly set parameters (`required_parameters`); only tools whose
  `supportedParameters` contain all of them are eligible (defaults are not requirements). Techniques flagged in the catalog
  (`PrivilegedValues`: `scanType=syn`, `method=icmp|tcp-ack|arp`) set `needs_raw_sockets`; agents reporting `RawSockets=false` skip them.
* Direct agents first: an agent that reaches a batch only through its default route leaves it to an **online** agent that reaches it
  directly (attached subnet or specific route) and can run the step; it takes the job once no such agent is online. Applied at claim
  time (`ClaimSelector`, peers = online agents) and in the job's `eligibleAgentIds`. Direct agents see the subnet first-hand (ARP, MACs).
* Dedup: unique `(scan_run_id, step_id, target_key, perspective)` prevents scanning the same batch twice from the same perspective.
* Assignment: pull-based claim with `SELECT … FOR UPDATE SKIP LOCKED`; weighted score = priority, free capacity, measured throughput
  (EWMA of targets/s per agent+interface+tool), age. Global caps per zone, per interface, per subnet (`/16` default) and per run rate.
* Lease: `leaseId`, `expiresAt`, `attempt`. Job heartbeat extends; expiry or `AgentWentOffline` → back to queue (attempt+1) until
  `maxAttempts` → Failed. Calls with a stale lease → 409 (no duplicate results). Results idempotent by `batchId`.
* Execution metrics are recorded per job (duration, targets/s) and feed the weights.
* Unassignable jobs: a queued job that no **online, authorized** agent can take (zone, network restriction, approved tool,
  reachability) for `unassignedJobTimeoutSeconds` (scan limits, default 900 s, 0 = wait forever) is cancelled by the sweeper.
  Its targets count as not covered: the step continues with the other jobs, the run ends `PartiallyCompleted` (or the step fails
  if none of its jobs could run), and nothing is marked gone. Jobs waiting only for a busy eligible agent keep waiting.

## 9. Workflow engine (stream C)

* Definitions: JSON (`ScanWorkflowDefinition`), validated (acyclic, known step ids, operation parameters, condition fields, depth),
  immutable versions. `IWorkflowRuntime` abstraction (start/cancel/signal) with an own DAG implementation; step executors
  (`IStepExecutor` per `ScanOperation`) are independent of the runtime so Elsa Workflows 3 can host them later.
* Agent steps create jobs through the planner; server steps call Kernel ports (`IDiscoveryRunProcessor`, `IFindingPublisher`).
* Data-flow validation (on save): input steps must produce observations (agent steps or `EvaluateCondition`, seen through to its
  sources); endpoint operations (DetectService, HttpProbe, TlsProbe, ExecuteSignatures) need a source with ports (ScanPorts,
  DetectService, HttpProbe, TlsProbe, ExecuteSignatures); PersistObservations, ComparePreviousScan and PublishFinding must have every
  agent step as an ancestor, and the last two also a PersistObservations step (coverage + all results ingested).
  RecheckMissing takes no input and must have every other agent step as an ancestor.
* **RecheckMissing** (agent plane, targets computed server-side): asks Discovery (`IRecheckTargetSource`) for known hosts (not Gone)
  and open TCP endpoints the run has **not** observed although a miss would count (complete coverage covering the target with the
  relevant operation, same rule as ComparePreviousScan); unstable hosts are always included (also Gone or with incomplete coverage)
  and listed first. It queues `DiscoverHosts` jobs for missing hosts and one `ScanPorts` job per distinct port set for missing
  endpoints (each host only on its own known ports) — existing capabilities, no new tool; out-of-scope targets are dropped by the
  planner. Parameters `attempts` (1–5 rounds, default 2), `delaySeconds` (0–3600 between rounds, default 30), `rate`. After a
  round's jobs finish the runtime re-runs the step after the delay; each round asks again, so only what is still missing is
  probed (dedup key salted per round). Its observations belong to the run, so a target that answered is not counted as a miss.
* Step input = observations of `Input.FromSteps` filtered by `Input.Filter`; `When` gates execution (else Skipped).
  Independent steps run in parallel. Timeouts, retries (`RetryPolicy`), `OnFailure`, cancellation, window expiry
  (`NotAfter` → cancel active jobs, run = `WindowExpired`, partial observations kept, coverage marked incomplete).
* Built-in workflow `standard-discovery` is seeded (DiscoverHosts → ScanPorts → DetectService → [HTTP: HttpProbe → ExecuteSignatures]
  [TLS: TlsProbe] → RecheckMissing (OnFailure = Continue) → PersistObservations → ComparePreviousScan → PublishFinding). Seeding
  only inserts the key when it is absent: existing databases keep their stored version until a new one is saved.
* Operations (closed enum `ScanOperation`, `OperationCatalog`): agent plane DiscoverHosts, ScanPorts, DetectService, HttpProbe,
  TlsProbe, ExecuteSignatures, RecheckMissing; server plane EvaluateCondition, PersistObservations, ComparePreviousScan, PublishFinding.
* Schedules: Quartz.NET (RAM store, rebuilt from DB at startup), cron + IANA time zone, allowed windows, overlap policy;
  `(scheduleId, fireTime)` unique → no duplicate runs.

## 10. Discovery & analysis (stream D)

* Raw observations append-only (`observations`), current state separate (`hosts`, `services`, `technologies`, `certificates`,
  `signature_matches`), user annotations separate (`asset_annotations`, audited) — user edits never overwrite evidence.
* Change events: NewHost, HostReappeared, HostGone, NewPort, PortGone, NewService, ServiceChanged, TechnologyChanged,
  TlsCertificateChanged, HttpResponseChanged, TimeOfDayVariance.
* "Gone" only after `missingThreshold` consecutive runs whose coverage **included** the target and the relevant operation;
  uncovered targets never count as misses. Flapping hosts tracked (state-change rate) and reported as unstable.
* Unstable hosts and changing responses: RecheckMissing re-probes missed targets (unstable hosts always) before the comparison, so
  a short outage is not a miss; unstable hosts never produce HostGone/HostReappeared noise. Each covering outcome is also counted
  per UTC hour (`hosts.HourlySeen/HourlyMissed`) → per-hour availability on the host detail. HTTP responses are kept per
  (path, UTC hour, fingerprint) (`http_snapshots`); consistent hour-dependent responses set `Service.TimeOfDayVariance`, emit one
  `TimeOfDayVariance` change (pattern in `after`, e.g. `/ → 03h UTC: 503 'Maintenance'; 14h UTC: 200 'App'`) and stop repeated
  HttpResponseChanged events for that hour pattern.
* **Interest score** (`InterestScorer`, 0–100, computed on read, reasons ordered by weight): counted findings by severity
  (`InterestScorer.CountsFinding` = open; the one place to exclude triaged false positives), classification tags (admin panel,
  staging/dev/test, IoT/camera/printer…), new in the last compared run / first seen < 7 days, technologies with versions,
  remote-admin/database/cleartext ports, web UI on a non-standard port, expired / soon-expiring / self-signed certificates, unstable
  host, time-of-day variance, plus `InterestInput.Extra` (hook for other analyzers, e.g. HTTP artifacts). Host score = max of its open
  services and its host-level signals. Lists sort/filter by it; exports carry `interestScore` + `interestReasons`.
* Technology confidence combines sources (tool-reported, banner, signature, port heuristic) into a score + method.
* Signatures: Nuclei YAML (active detection; validated: no `code`/`headless`/`javascript`/`file` protocols, no interactsh,
  no intrusive/dos/fuzz tags, default severities info/low), JSON classification rules (interpretation of observations),
  change rules (historical). Versioned; only **approved** versions are executable/applied.
* Export JSON/CSV; DefectDojo API v2 adapter (only selected signature findings, external ids stored, never plain open ports).

## 11. UI-facing REST API (implemented by A/C/D, consumed by E)

Conventions: JSON (camelCase, string enums); errors = RFC 7807 ProblemDetails (`errors` dict for validation);
paging `?page=1&pageSize=50` → `{ "items": [...], "total": n, "page": 1, "pageSize": 50 }`; ids are GUIDs unless noted.
Role shorthand: R=CanRead, E=CanEdit, M=CanManage, A=AdminOnly.

**Identity (A)**
* `POST /api/auth/login` {userName, password} → {accessToken, expiresAt, user:{id, userName, displayName, roles[]}} (anonymous)
* `GET /api/auth/me` (R) → user
* `GET|POST /api/users`, `PUT|DELETE /api/users/{id}`, `POST /api/users/{id}/password` (A) — user: {id, userName, displayName, roles[], isActive, createdAt, lastLoginAt}

**Agents & tools (A)**
* `GET /api/agents` (R) → [{agentId, hostname, status, isOnline, lastHeartbeatAt, registeredAt, osPlatform, osDescription, agentVersion,
  tools:[{id, version, capabilities[], approved}], interfaces[], routes[], declaredZones[], authorizedZones[], authorizedNetworkIds[],
  limits:{maxConcurrentJobs, maxRatePerSecond}, load?}] ; `GET /api/agents/{agentId}` (R)
* `POST /api/agents/{agentId}/status` {status: Active|Disabled|Blocked} (A); `PUT /api/agents/{agentId}/assignment`
  {authorizedZones[], authorizedNetworkIds[], maxConcurrentJobs?, maxRatePerSecond?} (A); `POST /api/agents/{agentId}/rotate-credentials` (A); `DELETE /api/agents/{agentId}` (A)
* `GET|POST /api/enrollment-tokens`, `DELETE /api/enrollment-tokens/{id}` (A) — create {name, expiresInHours, maxUses, autoApprove, zones[]} → {id, token (shown once), expiresAt}
  (`zones[]` = zones pre-authorized for agents enrolling with this token)
* `GET /api/tools` (R) → [{toolId, approved, enabled, capabilities[], versions[], agentCount, firstSeenAt}]; `PUT /api/tools/{toolId}` {approved, enabled} (A)

**Networks & scope (A)**
* `GET /api/networks` (R) → [{id, name, description, zone, ranges[], exclusions[], tags[], maxRatePerSecond?, enabled, addressCount, createdAt, updatedAt}]
* `POST /api/networks` (M), `PUT /api/networks/{id}` (E), `DELETE /api/networks/{id}` (M), `GET /api/networks/{id}` (R)
* `GET /api/networks/agent-subnets` (R) → [{cidr, source: interface|route, zone|null, candidateZones[], addressCount,
  seenBy[{agentId, interfaceName, address, online, gateway?}], scope: full|partial|none, proposedRanges[], existingNetworks[],
  management, large}] — subnets of active agents' interfaces and gateway routes (loopback, link-local, multicast, single addresses,
  IPv6 > 65 536 and IPv4 > /8 skipped). `zone` = the agent's only authorized zone (null if several); `proposedRanges` = part inside
  the scope policy minus networks of those zones (what a new network adds, no overlaps); `management` = contains the address the
  agent registered from while the agent has other subnets; `large` = IPv4 > 65 536. The UI creates networks with the normal
  `POST /api/networks` (tag `agent-subnet`); widening the policy stays an explicit Admin `PUT /api/scope-policy`.
* `GET /api/networks/export?format=json|csv` (R); `POST /api/networks/import?format=json|csv` (M, raw body) → {created, updated, errors[]}
* `GET /api/zones` (R) → [{name, description, networkCount}]; `POST /api/zones` (M); `DELETE /api/zones/{name}` (M)
* `GET /api/scope-policy` (R) / `PUT` (A) → {allowed[], excluded[], updatedAt}
* `GET|PUT /api/settings` (A) → {values:{key:value}}; `GET /api/audit?page&pageSize&action&entityType&userId` (A) → paged
  [{id, occurredAt, userId, userName, action, entityType, entityId, details, ipAddress}]

**Workflows, schedules, scans, jobs (C)**
* `GET /api/operations` (R) → {operations: OperationDescriptor[], capabilityMapping:{operation: capability}}
* `GET /api/workflows` (R) → [{key, latestVersion, name, description, updatedAt}]; `GET /api/workflows/{key}` (R) → {key, version, definition, createdAt, createdBy}
* `GET /api/workflows/{key}/versions[/{version}]` (R); `POST /api/workflows` (M, definition → v1); `POST /api/workflows/{key}/versions` (M); `POST /api/workflows/validate` (R) → {valid, errors[]}
* `GET /api/schedules` (R) → [{id, name, cronExpression, timeZone, workflowKey, workflowVersion?, networkIds[], priority, maxRatePerSecond?,
  windowDurationMinutes?, allowedWindows:[{daysOfWeek[], start:"HH:mm", end:"HH:mm"}], overlapPolicy: Skip|CancelPrevious|Queue, enabled,
  nextFireAt?, lastRunId?, lastRunStatus?}]; `POST` (M), `PUT /{id}` (E), `DELETE /{id}` (M), `POST /{id}/trigger` (E) → {scanRunId}, `POST /{id}/pause|resume` (E)
* `GET /api/scans?status&page&pageSize` (R) → paged [{id, name, status: Pending|Running|Completed|PartiallyCompleted|Failed|Cancelled|WindowExpired,
  workflowKey, workflowVersion, networkIds[], triggeredBy, priority, createdAt, startedAt?, finishedAt?, notAfter?,
  progress:{jobsTotal, jobsQueued, jobsRunning, jobsCompleted, jobsFailed, percent}, coverageComplete}]
* `POST /api/scans` (E) {name, workflowKey, workflowVersion?, networkIds[], priority?, maxRatePerSecond?, windowMinutes?} → run
* `GET /api/scans/{id}` (R) → run + steps:[{stepId, operation, status: Pending|Running|Completed|Skipped|Failed|Cancelled, jobsTotal, jobsCompleted, startedAt?, finishedAt?, message?}]
* `POST /api/scans/{id}/cancel` (E); `GET /api/scans/{id}/jobs` (R); `GET /api/scans/{id}/events?after=` (R) → ScanExecutionEvent[]
* `GET /api/jobs?status&agentId&page` (R) → paged [{id, scanRunId, stepId, operation, status: Queued|Leased|Completed|Failed|Cancelled,
  agentId?, interfaceName?, toolId?, targetSummary, targetCount, attempt, maxAttempts, createdAt, startedAt?, finishedAt?, durationMs?, error?, progressPercent?}]
* `GET /api/jobs/{id}` (R); `POST /api/jobs/{id}/cancel` (E); `POST /api/jobs/{id}/retry` (E)
* `GET /api/scan-limits` (R) / `PUT` (A) → {defaultBatchSize, leaseDurationSeconds, maxAttempts, maxConcurrentJobsPerZone, maxConcurrentJobsPerInterface,
  maxConcurrentJobsPerSubnet, subnetPrefixLength, maxRatePerSecondGlobal}
* `GET /api/stats/planner` (R) → {queue:{queued, leased}, performance:[{agentId, interfaceName, toolId, jobsCompleted, avgDurationMs, avgTargetsPerSecond}]}
* SignalR `/hubs/scans` (JWT via `access_token` query): server → client `scanEvent(ScanExecutionEvent)`; client → server `JoinRun(runId)`.

**Discovery, analytics, signatures, integrations (D)**
* `GET /api/dashboard/summary` (R) → {hostsTotal, hostsActive, servicesTotal, changesLast24h, findingsOpen, lastScanAt?}
* `GET /api/dashboard/insights?days=14` (R, days 1–90) → {topFindings: Finding[10] (counted, severity then recency), topServices:
  Service[10] (highest interest score, with reasons), changesByDay:[{date: yyyy-MM-dd UTC, total, byType:{type: count}}] (every day of
  the window), recentScans:[{id, name, status, workflowKey, createdAt, startedAt?, finishedAt?, durationSeconds?, coverageComplete,
  changesDetected?}] (from Scanning via `IRecentScanRunReader`), unstableHosts, timeOfDayVarianceServices}
* `GET /api/assets/hosts?search&status&zone&networkDevice&sort=interest&minInterest&page&pageSize` (R) → paged [{id, address, hostnames[], status: Active|Unreachable|Gone|Unknown, unstable,
  interestScore, interestReasons[],
  firstSeenAt, lastSeenAt, lastScannedAt?, openPortCount, technologies[], zone?, macAddress?, macVendor?, networkDevice, networkDeviceConfidence?: high|low,
  annotation?:{description, classification, businessState, owner, tags[]}}] (`networkDevice=true` → only network-device interfaces)
* `GET /api/assets/hosts/{id}` (R) → host + services[] + technologies[] + certificates[] + findings[] + recentChanges[] +
  deviceInterfaces:[{hostId, zone, address}] (the other zones' interfaces of the same network device) +
  hourlyVisibility:[{hour 0–23 UTC, seen, missed}] (covering scans per hour) + interestScore + interestReasons[]
* `PUT /api/assets/hosts/{id}/annotation` (E) {description, classification, businessState, owner, tags[]}
* `GET /api/assets/services?port&serviceName&search&sort=interest&minInterest&page` (R) → paged [{id, hostId, address, port, transport, state: Open|Gone, serviceName, product, version,
  http?:{url, statusCode, title, webServer}, tls?:{subjectCommonName, issuer, notAfter, fingerprintSha256}, technologies[], confidence?, firstSeenAt, lastSeenAt,
  timeOfDayVariance, hourlyResponses?:[{hour, seen, missed: 0, response}] (only with time-of-day variance), interestScore, interestReasons[]}]
* `GET /api/assets/technologies` (R) → [{name, version?, category?, hostCount, serviceCount, confidence}]
* `GET /api/observations?hostId&scanRunId&kind&page` (R) → paged raw observations
* `GET /api/changes?since&type&hostId&scanRunId&page` (R) → paged [{id, detectedAt, scanRunId, type, hostId?, address, port?, summary, before?, after?, severity}]
* `GET /api/scans/{runId}/diff?baseline={runId}` (R) → {added[], removed[], changed[]}
* `GET /api/topology?zone&networkId&search` (R) → {perspectives:[{agentId, interfaceName?, zone?}], zones:[{name, subnetCount, hostCount}],
  devices:[{id (= MAC), macAddress, macVendor?, confidence: high|low, zones[], interfaces:[{hostId, zone, address}]}], subnets:[{id, cidr, zone?, hostCount}],
  hosts:[{id, address, hostnames[], status, unstable, subnet, zone?, lastSeenAt, macAddress?, macVendor?, deviceId?, sharedMac, openPortCount,
  services:[{port, transport, serviceName?, product?, version?, url?, isWeb, tls}], technologies[], observedBy:[{agentId, interfaceName?}]}], truncated}
  (subnets: IPv4 /24, IPv6 /64; max 5000 hosts; devices = those with an interface among the returned hosts, with all their zones/interfaces).
  Service DTOs carry `url` (best clickable URL: HTTP probe URL, else https/http by TLS/service name).
* `GET /api/findings?severity&status&page` (R) → paged [{id, signatureId, signatureVersion, name, severity, hostId, address, port?, matchedAt, evidence?, status: Open|Resolved, firstSeenAt, lastSeenAt, externalRefs:[{system, externalId}]}]
* `GET /api/export/{hosts|services|changes|findings}?format=json|csv` (R); `POST /api/import/assets?format=json|csv` (M) → {imported, updated, errors[]}
* `GET /api/signatures?kind&status` (R) → [{id, name, kind: NucleiTemplate|ClassificationRule|ChangeRule, latestVersion, approvedVersion?, status: Draft|Approved|Retired, severity?, tags[], updatedAt}]
* `GET /api/signatures/{id}` (R) → + versions:[{version, content, sha256, createdAt, createdBy, approvedAt?, approvedBy?}]
* `POST /api/signatures` (M) {id, name, kind, content}; `POST /api/signatures/{id}/versions` (M) {content}; `POST /api/signatures/{id}/versions/{version}/approve` (A);
  `POST /api/signatures/{id}/retire` (M); `POST /api/signatures/validate` (R) {kind, content} → {valid, errors[], warnings[]}
* `GET|PUT /api/integrations/defectdojo` (A) {enabled, baseUrl, apiKey (write-only; GET returns hasApiKey), productId, engagementId, minimumSeverity, verifyTls};
  `POST /api/integrations/defectdojo/test` (A); `POST /api/integrations/defectdojo/export` (M) {findingIds[]} → {exported, skipped, errors[]}

**Health/observability (A)**: `/health/live`, `/health/ready`; OTLP export (`OpenTelemetry:OtlpEndpoint`).

## 12. Agent API (A: register/heartbeat/rotate, C: jobs)

`POST /api/agents/register`, `/heartbeat`, `/credentials/rotate`, `/jobs/claim`, `/jobs/{id}/heartbeat`, `/jobs/{id}/results`,
`/jobs/{id}/complete`, `/jobs/{id}/fail` — DTOs in `Contracts` (`AgentApiRoutes`). All require `Policies.Agent` except the first
registration with an enrollment token. Request bodies may be gzip (`Content-Encoding: gzip`; server enables request decompression).
Status codes: 401 bad credentials, 403 agent disabled/blocked, 404 unknown job, 409 stale lease / job not assigned to caller, 422 invalid payload.

## 13. Observability

OpenTelemetry traces + metrics (meter `WebScan`): `webscan.ips_scanned` (counter → IPs/s), `webscan.job.duration`, `webscan.queue.length`,
`webscan.agents.active`, `webscan.job.timeouts`, `webscan.job.failures`, `webscan.interface.throughput`, `webscan.workflow.step.duration`.
ActivitySource `WebScan`. Docker Compose profile `observability`: OTel Collector → Prometheus → Grafana (Prometheus + PostgreSQL datasources).

## 14. Local ports

Server `http://localhost:5080` / `https://localhost:5443`; frontend dev `http://localhost:5173` (Vite proxy `/api`, `/hubs` → server);
PostgreSQL 5432; RabbitMQ 5672 / 15672; Grafana 3000. Compose files in `deploy/docker`, test lab in `tests/TestLab`.

## 15. Decisions log

* Modular monolith with schema-per-module DbContexts → parallel development without migration conflicts, clear boundaries.
* Pull-based HTTPS agent protocol (no inbound connections to agents); SignalR only for the UI.
* Quartz RAM store + DB as source of truth for schedules; `(scheduleId, fireTime)` uniqueness for idempotent triggering.
* Deterministic weighted planner (no ML). Tool selection by capability, tool definitions by manifest.
* Own JSON DAG engine behind `IWorkflowRuntime`; Elsa 3 can be plugged in later by hosting `IStepExecutor`s as activities.

## 16. Implementation notes (after integration)

Deviations and clarifications agreed during integration (code is the source of truth):

* Validation errors return **422** ProblemDetails with an `errors` dictionary (not 400). Conflicts (duplicate names/ids) return 409 ProblemDetails.
* `/api/scans*` endpoints live in the Workflows module (run detail needs step state); Workflows references Scanning directly.
  `/api/scans/{id}/jobs` is paged like `/api/jobs`. Job events go to the SignalR run group (`JoinRun`); run-level events go to all clients.
* Disabled/Blocked agents authenticate but every agent policy rejects them (403). Re-enrolling an existing agent id returns 409;
  agents persist credentials in `Agent:DataDirectory` (`/var/lib/webscan-agent` in the image, a volume in Compose).
* Inventory hash = SHA-256 of the contract JSON of `{tools, interfaces, routes}` (agent); the server adopts it from the first
  heartbeat after registration and requests re-registration on mismatch.
* Cron uses Quartz syntax (seconds first). Skipped schedule fires are reported as `RunCancelled` events without a run id and
  `data.reason` = `outside-window` | `previous-run-active` | `window-over`.
* `RunCoverage.Complete` is false if any job failed/was cancelled or the window expired. After window expiry only
  `PersistObservations` runs (after leased jobs drained) — partial data kept, nothing marked gone.
* PersistObservations waits until every result batch accepted by Scanning for the run is ingested (`IRunBatchCatalog`), bounded by
  `Discovery:IngestMaxWaitSeconds`.
* Classification-rule results are stored as info findings (source `classification-rule`); host DTOs expose `classifications[]`.
* Signature approval of high/critical versions requires a note (`requiresApprovalNote`); bundle hash format shared with the agent:
  SHA-256 over UTF-8 `{id}\n{version}\n{content}\n` per item, ordered by id.
* DefectDojo export uses `POST /api/v2/findings/` within a lazily created "WebScan" test (Generic Findings Import) and `PATCH` for
  changed findings; external id + content hash stored per finding.
* Quartz keeps a process-wide static log provider; hosts created repeatedly in one process (tests) must reset it
  (`LogContext.SetCurrentLogProvider`).
* Planner keeps **one interface per (agent, scan run, network)** across all workflow steps; a busy pinned interface means waiting,
  never switching perspective. Different networks of a run may still use different interfaces of one agent in parallel.
* Admin panel: workflows are edited as a React Flow graph (palette, inspector, condition builder) with a synced JSON tab;
  topology map (network devices + agent interfaces → zones → subnets → hosts) and inventory graph (subnet → host → port cards); every `address:port` opens in a new tab.
* **Asset identity is (zone, address)**: the same IP in two zones is two hosts (zone = the scanned network's zone, `""` = default).
  Services, findings, change events, annotations (import/export carry `zone`; a zone-less import row matches only an address
  that exists in exactly one zone, else it is reported as ambiguous) and run diff keys (`endpoint|{zone}|{addr}|…`) are zone-scoped;
  `RunCoverage.CoveredHostsByZone/CoveredEndpointsByZone` (built per job zone) make miss/gone counting zone-aware (flat lists = all
  zones); `/api/topology` subnet ids are `{zone}|{cidr}`. Hosts keep the latest **MAC + vendor** (`AA:BB:CC:DD:EE:FF`; history in raw
  observations) as an attribute only, never identity (randomized MACs; behind a router you see the router's MAC). The agent image
  sets `NMAP_PRIVILEGED=1` so non-root nmap uses its raw-socket capability: same-subnet discovery then uses ARP and reports MACs
  (natively on macOS without root nmap cannot see MACs).
* **Zone = separate IP address space** (routed segment / VLAN / VRF) of the one organization network; a host record is one IP interface
  in one zone. **Network devices** are inferred on read (no table): one MAC on current (not Gone) hosts of **two or more zones** = one
  router / L3 switch / firewall / multi-homed box with an interface in each; VRRP `00:00:5E:00:01:xx` / HSRP `00:00:0C:07:AC:xx` MACs
  are devices on their own. Broadcast, multicast and all-zero MACs are ignored; locally administered MACs (`02:42:…` Docker/VM) give
  confidence **low** (they repeat by accident). A MAC on several IPs of **one** zone is only `sharedMac` (aliases, proxy-ARP). The
  topology map is hierarchical: devices + agent interfaces → zones → subnets → host grids. Limits: a MAC is visible only to an agent on
  the same L2 segment with ARP privileges, so devices are found only where agents sit; routers with a distinct MAC per interface are
  not linked by this rule; one virtual-router MAC (same VRID/group) in two zones is linked as one device.
* Agent tool manifest format and extensibility: [docs/TOOLS.md](docs/TOOLS.md). Additional placeholder `{ports}` (nmap groups hosts by
  identical port sets so it never scans endpoints outside the job).

Known limitations (MVP): JWTs stay valid until expiry after user deactivation; forwarded headers not configured (audit IP = proxy);
job rate fixed at lease time; PortGone does not know the exact port list of the previous ScanPorts step; HTTP change detection ignores
body hashes; UDP endpoints not mapped to nmap `-sU`; Quartz uses an in-memory store (single active scheduler node — DB uniqueness on
`(scheduleId, fireTime)` prevents duplicate runs); physical L2 topology (switch ports, LLDP/CDP) is not modelled; L3 devices are inferred only from MACs shared across zones (see above).
