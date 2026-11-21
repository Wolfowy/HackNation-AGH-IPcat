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
* Dedup: unique `(scan_run_id, step_id, target_key, perspective)` prevents scanning the same batch twice from the same perspective.
* Assignment: pull-based claim with `SELECT … FOR UPDATE SKIP LOCKED`; weighted score = priority, free capacity, measured throughput
  (EWMA of targets/s per agent+interface+tool), age. Global caps per zone, per interface, per subnet (`/16` default) and per run rate.
* Lease: `leaseId`, `expiresAt`, `attempt`. Job heartbeat extends; expiry or `AgentWentOffline` → back to queue (attempt+1) until
  `maxAttempts` → Failed. Calls with a stale lease → 409 (no duplicate results). Results idempotent by `batchId`.
* Execution metrics are recorded per job (duration, targets/s) and feed the weights.

## 9. Workflow engine (stream C)

* Definitions: JSON (`ScanWorkflowDefinition`), validated (acyclic, known step ids, operation parameters, condition fields, depth),
  immutable versions. `IWorkflowRuntime` abstraction (start/cancel/signal) with an own DAG implementation; step executors
  (`IStepExecutor` per `ScanOperation`) are independent of the runtime so Elsa Workflows 3 can host them later.
* Agent steps create jobs through the planner; server steps call Kernel ports (`IDiscoveryRunProcessor`, `IFindingPublisher`).
* Step input = observations of `Input.FromSteps` filtered by `Input.Filter`; `When` gates execution (else Skipped).
  Independent steps run in parallel. Timeouts, retries (`RetryPolicy`), `OnFailure`, cancellation, window expiry
  (`NotAfter` → cancel active jobs, run = `WindowExpired`, partial observations kept, coverage marked incomplete).
* Built-in workflow `standard-discovery` is seeded (DiscoverHosts → ScanPorts → DetectService → [HTTP: HttpProbe → ExecuteSignatures]
  [TLS: TlsProbe] → PersistObservations → ComparePreviousScan → PublishFinding).
* Schedules: Quartz.NET (RAM store, rebuilt from DB at startup), cron + IANA time zone, allowed windows, overlap policy;
  `(scheduleId, fireTime)` unique → no duplicate runs.

## 10. Discovery & analysis (stream D)

* Raw observations append-only (`observations`), current state separate (`hosts`, `services`, `technologies`, `certificates`,
  `signature_matches`), user annotations separate (`asset_annotations`, audited) — user edits never overwrite evidence.
* Change events: NewHost, HostReappeared, HostGone, NewPort, PortGone, NewService, ServiceChanged, TechnologyChanged,
  TlsCertificateChanged, HttpResponseChanged, TimeOfDayVariance.
* "Gone" only after `missingThreshold` consecutive runs whose coverage **included** the target and the relevant operation;
  uncovered targets never count as misses. Flapping hosts tracked (state-change rate) and reported as unstable.
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
* `GET /api/assets/hosts?search&status&zone&page&pageSize` (R) → paged [{id, address, hostnames[], status: Active|Unreachable|Gone|Unknown, unstable,
  firstSeenAt, lastSeenAt, lastScannedAt?, openPortCount, technologies[], zone?, annotation?:{description, classification, businessState, owner, tags[]}}]
* `GET /api/assets/hosts/{id}` (R) → host + services[] + technologies[] + certificates[] + findings[] + recentChanges[]
* `PUT /api/assets/hosts/{id}/annotation` (E) {description, classification, businessState, owner, tags[]}
* `GET /api/assets/services?port&serviceName&search&page` (R) → paged [{id, hostId, address, port, transport, state: Open|Gone, serviceName, product, version,
  http?:{url, statusCode, title, webServer}, tls?:{subjectCommonName, issuer, notAfter, fingerprintSha256}, technologies[], confidence?, firstSeenAt, lastSeenAt}]
* `GET /api/assets/technologies` (R) → [{name, version?, category?, hostCount, serviceCount, confidence}]
* `GET /api/observations?hostId&scanRunId&kind&page` (R) → paged raw observations
* `GET /api/changes?since&type&hostId&scanRunId&page` (R) → paged [{id, detectedAt, scanRunId, type, hostId?, address, port?, summary, before?, after?, severity}]
* `GET /api/scans/{runId}/diff?baseline={runId}` (R) → {added[], removed[], changed[]}
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
