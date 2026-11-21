using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace WebScan.Server.Modules.Discovery.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "discovery");

            migrationBuilder.CreateTable(
                name: "asset_annotation_revisions",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Classification = table.Column<string>(type: "text", nullable: true),
                    BusinessState = table.Column<string>(type: "text", nullable: true),
                    Owner = table.Column<string>(type: "text", nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    ChangedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ChangedBy = table.Column<string>(type: "text", nullable: true),
                    Source = table.Column<string>(type: "text", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_asset_annotation_revisions", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "asset_annotations",
                schema: "discovery",
                columns: table => new
                {
                    Address = table.Column<string>(type: "text", nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    Classification = table.Column<string>(type: "text", nullable: true),
                    BusinessState = table.Column<string>(type: "text", nullable: true),
                    Owner = table.Column<string>(type: "text", nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_asset_annotations", x => x.Address);
                });

            migrationBuilder.CreateTable(
                name: "certificates",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceId = table.Column<Guid>(type: "uuid", nullable: false),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    FingerprintSha256 = table.Column<string>(type: "text", nullable: false),
                    SubjectCommonName = table.Column<string>(type: "text", nullable: true),
                    SubjectAlternativeNames = table.Column<List<string>>(type: "text[]", nullable: false),
                    Issuer = table.Column<string>(type: "text", nullable: true),
                    NotBefore = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    NotAfter = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SerialNumber = table.Column<string>(type: "text", nullable: true),
                    SelfSigned = table.Column<bool>(type: "boolean", nullable: true),
                    TlsVersion = table.Column<string>(type: "text", nullable: true),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_certificates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "change_events",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DetectedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ScanRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: true),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: true),
                    Summary = table.Column<string>(type: "text", nullable: false),
                    Before = table.Column<string>(type: "text", nullable: true),
                    After = table.Column<string>(type: "text", nullable: true),
                    Severity = table.Column<string>(type: "text", nullable: false),
                    RaisedBy = table.Column<List<string>>(type: "text[]", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_change_events", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "hosts",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Hostnames = table.Column<List<string>>(type: "text[]", nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Unstable = table.Column<bool>(type: "boolean", nullable: false),
                    Zone = table.Column<string>(type: "text", nullable: true),
                    MacAddress = table.Column<string>(type: "text", nullable: true),
                    MacVendor = table.Column<string>(type: "text", nullable: true),
                    OsGuess = table.Column<string>(type: "text", nullable: true),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastScannedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    FirstSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    LastSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    ConsecutiveMisses = table.Column<int>(type: "integer", nullable: false),
                    StateChangeCount = table.Column<int>(type: "integer", nullable: false),
                    StateHistory = table.Column<string>(type: "character varying(10)", maxLength: 10, nullable: false),
                    ComparedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_hosts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "http_snapshots",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceId = table.Column<Guid>(type: "uuid", nullable: false),
                    Path = table.Column<string>(type: "text", nullable: false),
                    HourBucket = table.Column<int>(type: "integer", nullable: false),
                    Fingerprint = table.Column<string>(type: "text", nullable: false),
                    StatusCode = table.Column<int>(type: "integer", nullable: true),
                    Title = table.Column<string>(type: "text", nullable: true),
                    WebServer = table.Column<string>(type: "text", nullable: true),
                    BodySha256 = table.Column<string>(type: "text", nullable: true),
                    FaviconHash = table.Column<string>(type: "text", nullable: true),
                    ObservationCount = table.Column<int>(type: "integer", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    FirstScanRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    LastScanRunId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_http_snapshots", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "observations",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    ScanRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    BatchId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObservationId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    AgentId = table.Column<string>(type: "text", nullable: false),
                    InterfaceName = table.Column<string>(type: "text", nullable: true),
                    Zone = table.Column<string>(type: "text", nullable: true),
                    WorkflowStepId = table.Column<string>(type: "text", nullable: true),
                    Operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: true),
                    Transport = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    ObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ReceivedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Payload = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_observations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "processed_batches",
                schema: "discovery",
                columns: table => new
                {
                    BatchId = table.Column<Guid>(type: "uuid", nullable: false),
                    JobId = table.Column<Guid>(type: "uuid", nullable: false),
                    ScanRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    Sequence = table.Column<int>(type: "integer", nullable: false),
                    ObservationsReceived = table.Column<int>(type: "integer", nullable: false),
                    ObservationsAccepted = table.Column<int>(type: "integer", nullable: false),
                    ProcessedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_processed_batches", x => x.BatchId);
                });

            migrationBuilder.CreateTable(
                name: "run_processing",
                schema: "discovery",
                columns: table => new
                {
                    ScanRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    CoverageComplete = table.Column<bool>(type: "boolean", nullable: false),
                    CoveredHosts = table.Column<List<string>>(type: "text[]", nullable: false),
                    CoveredEndpoints = table.Column<List<string>>(type: "text[]", nullable: false),
                    OperationsExecuted = table.Column<List<string>>(type: "text[]", nullable: false),
                    PersistedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ComparedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ChangesDetected = table.Column<int>(type: "integer", nullable: true),
                    ChangesByType = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_run_processing", x => x.ScanRunId);
                });

            migrationBuilder.CreateTable(
                name: "services",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    Transport = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    State = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ServiceName = table.Column<string>(type: "text", nullable: true),
                    Product = table.Column<string>(type: "text", nullable: true),
                    Version = table.Column<string>(type: "text", nullable: true),
                    ExtraInfo = table.Column<string>(type: "text", nullable: true),
                    Banner = table.Column<string>(type: "text", nullable: true),
                    Tunnel = table.Column<string>(type: "text", nullable: true),
                    Cpe = table.Column<List<string>>(type: "text[]", nullable: false),
                    Confidence = table.Column<double>(type: "double precision", nullable: true),
                    ConfidenceMethod = table.Column<string>(type: "text", nullable: true),
                    AttributesRunId = table.Column<Guid>(type: "uuid", nullable: true),
                    HttpUrl = table.Column<string>(type: "text", nullable: true),
                    HttpStatusCode = table.Column<int>(type: "integer", nullable: true),
                    HttpTitle = table.Column<string>(type: "text", nullable: true),
                    HttpWebServer = table.Column<string>(type: "text", nullable: true),
                    HttpObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CurrentCertFingerprint = table.Column<string>(type: "text", nullable: true),
                    TlsObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    TimeOfDayVariance = table.Column<bool>(type: "boolean", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    FirstSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    LastSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    ConsecutiveMisses = table.Column<int>(type: "integer", nullable: false),
                    ComparedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ComparedServiceName = table.Column<string>(type: "text", nullable: true),
                    ComparedSummary = table.Column<string>(type: "text", nullable: true),
                    ComparedCertFingerprint = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_services", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "signature_matches",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceId = table.Column<Guid>(type: "uuid", nullable: true),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Hostname = table.Column<string>(type: "text", nullable: true),
                    Port = table.Column<int>(type: "integer", nullable: true),
                    Transport = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    SignatureId = table.Column<string>(type: "text", nullable: false),
                    SignatureVersion = table.Column<int>(type: "integer", nullable: true),
                    Name = table.Column<string>(type: "text", nullable: false),
                    Severity = table.Column<string>(type: "text", nullable: false),
                    Source = table.Column<string>(type: "text", nullable: false),
                    MatcherName = table.Column<string>(type: "text", nullable: true),
                    MatchedUrl = table.Column<string>(type: "text", nullable: true),
                    Evidence = table.Column<string>(type: "text", nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    ClassificationTag = table.Column<string>(type: "text", nullable: true),
                    ConfidenceScore = table.Column<double>(type: "double precision", nullable: false),
                    ConfidenceMethod = table.Column<string>(type: "text", nullable: false),
                    MatchedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    ConsecutiveMisses = table.Column<int>(type: "integer", nullable: false),
                    ResolvedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    PublishedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ExternalRefs = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_signature_matches", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "technologies",
                schema: "discovery",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    HostId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceId = table.Column<Guid>(type: "uuid", nullable: true),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: true),
                    Name = table.Column<string>(type: "text", nullable: false),
                    NameKey = table.Column<string>(type: "text", nullable: false),
                    Version = table.Column<string>(type: "text", nullable: true),
                    VersionScore = table.Column<double>(type: "double precision", nullable: false),
                    Category = table.Column<string>(type: "text", nullable: true),
                    Confidence = table.Column<double>(type: "double precision", nullable: false),
                    ConfidenceMethod = table.Column<string>(type: "text", nullable: false),
                    Sources = table.Column<List<string>>(type: "text[]", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastSeenRunId = table.Column<Guid>(type: "uuid", nullable: false),
                    ComparedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ComparedVersion = table.Column<string>(type: "text", nullable: true),
                    Evidence = table.Column<string>(type: "jsonb", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_technologies", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_asset_annotation_revisions_Address_ChangedAt",
                schema: "discovery",
                table: "asset_annotation_revisions",
                columns: new[] { "Address", "ChangedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_certificates_HostId",
                schema: "discovery",
                table: "certificates",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_certificates_ServiceId_FingerprintSha256",
                schema: "discovery",
                table: "certificates",
                columns: new[] { "ServiceId", "FingerprintSha256" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_change_events_DetectedAt",
                schema: "discovery",
                table: "change_events",
                column: "DetectedAt");

            migrationBuilder.CreateIndex(
                name: "IX_change_events_HostId",
                schema: "discovery",
                table: "change_events",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_change_events_ScanRunId",
                schema: "discovery",
                table: "change_events",
                column: "ScanRunId");

            migrationBuilder.CreateIndex(
                name: "IX_hosts_Address",
                schema: "discovery",
                table: "hosts",
                column: "Address",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_hosts_Status",
                schema: "discovery",
                table: "hosts",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_http_snapshots_HostId",
                schema: "discovery",
                table: "http_snapshots",
                column: "HostId");

            migrationBuilder.CreateIndex(
                name: "IX_http_snapshots_ServiceId_Path_HourBucket_Fingerprint",
                schema: "discovery",
                table: "http_snapshots",
                columns: new[] { "ServiceId", "Path", "HourBucket", "Fingerprint" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_observations_Address_ObservedAt",
                schema: "discovery",
                table: "observations",
                columns: new[] { "Address", "ObservedAt" });

            migrationBuilder.CreateIndex(
                name: "IX_observations_JobId_ObservationId",
                schema: "discovery",
                table: "observations",
                columns: new[] { "JobId", "ObservationId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_observations_ScanRunId_Kind",
                schema: "discovery",
                table: "observations",
                columns: new[] { "ScanRunId", "Kind" });

            migrationBuilder.CreateIndex(
                name: "IX_processed_batches_ScanRunId",
                schema: "discovery",
                table: "processed_batches",
                column: "ScanRunId");

            migrationBuilder.CreateIndex(
                name: "IX_services_HostId_Port_Transport",
                schema: "discovery",
                table: "services",
                columns: new[] { "HostId", "Port", "Transport" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_services_Port_State",
                schema: "discovery",
                table: "services",
                columns: new[] { "Port", "State" });

            migrationBuilder.CreateIndex(
                name: "IX_signature_matches_HostId_Port_SignatureId",
                schema: "discovery",
                table: "signature_matches",
                columns: new[] { "HostId", "Port", "SignatureId" },
                unique: true)
                .Annotation("Npgsql:NullsDistinct", false);

            migrationBuilder.CreateIndex(
                name: "IX_signature_matches_LastSeenRunId",
                schema: "discovery",
                table: "signature_matches",
                column: "LastSeenRunId");

            migrationBuilder.CreateIndex(
                name: "IX_signature_matches_Status_Severity",
                schema: "discovery",
                table: "signature_matches",
                columns: new[] { "Status", "Severity" });

            migrationBuilder.CreateIndex(
                name: "IX_technologies_HostId_Port_NameKey",
                schema: "discovery",
                table: "technologies",
                columns: new[] { "HostId", "Port", "NameKey" },
                unique: true)
                .Annotation("Npgsql:NullsDistinct", false);

            migrationBuilder.CreateIndex(
                name: "IX_technologies_NameKey",
                schema: "discovery",
                table: "technologies",
                column: "NameKey");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "asset_annotation_revisions",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "asset_annotations",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "certificates",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "change_events",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "hosts",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "http_snapshots",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "observations",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "processed_batches",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "run_processing",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "services",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "signature_matches",
                schema: "discovery");

            migrationBuilder.DropTable(
                name: "technologies",
                schema: "discovery");
        }
    }
}
