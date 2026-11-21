using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace WebScan.Server.Modules.Scanning.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "scanning");

            migrationBuilder.CreateTable(
                name: "job_performance",
                schema: "scanning",
                columns: table => new
                {
                    agent_id = table.Column<string>(type: "text", nullable: false),
                    interface_name = table.Column<string>(type: "text", nullable: false),
                    tool_id = table.Column<string>(type: "text", nullable: false),
                    jobs_completed = table.Column<long>(type: "bigint", nullable: false),
                    avg_duration_ms = table.Column<double>(type: "double precision", nullable: false),
                    avg_targets_per_second = table.Column<double>(type: "double precision", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_job_performance", x => new { x.agent_id, x.interface_name, x.tool_id });
                });

            migrationBuilder.CreateTable(
                name: "result_batches",
                schema: "scanning",
                columns: table => new
                {
                    batch_id = table.Column<Guid>(type: "uuid", nullable: false),
                    job_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scan_run_id = table.Column<Guid>(type: "uuid", nullable: false),
                    step_id = table.Column<string>(type: "text", nullable: false),
                    lease_id = table.Column<Guid>(type: "uuid", nullable: false),
                    sequence = table.Column<int>(type: "integer", nullable: false),
                    observation_count = table.Column<int>(type: "integer", nullable: false),
                    received_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    payload_json = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_result_batches", x => x.batch_id);
                });

            migrationBuilder.CreateTable(
                name: "scan_events",
                schema: "scanning",
                columns: table => new
                {
                    seq = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    event_id = table.Column<Guid>(type: "uuid", nullable: false),
                    scan_run_id = table.Column<Guid>(type: "uuid", nullable: true),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    type = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    payload_json = table.Column<string>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_events", x => x.seq);
                });

            migrationBuilder.CreateTable(
                name: "scan_jobs",
                schema: "scanning",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    scan_run_id = table.Column<Guid>(type: "uuid", nullable: false),
                    workflow_run_id = table.Column<Guid>(type: "uuid", nullable: true),
                    step_id = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    operation = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    target_key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    perspective_key = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    target_summary = table.Column<string>(type: "text", nullable: false),
                    target_count = table.Column<long>(type: "bigint", nullable: false),
                    reach_targets = table.Column<List<string>>(type: "text[]", nullable: false),
                    capability = table.Column<string>(type: "text", nullable: false),
                    preferred_tool_id = table.Column<string>(type: "text", nullable: true),
                    zone = table.Column<string>(type: "text", nullable: false),
                    network_id = table.Column<Guid>(type: "uuid", nullable: false),
                    subnet_key = table.Column<string>(type: "text", nullable: true),
                    priority = table.Column<int>(type: "integer", nullable: false),
                    requested_rate_per_second = table.Column<int>(type: "integer", nullable: false),
                    step_max_concurrency = table.Column<int>(type: "integer", nullable: false),
                    timeout_seconds = table.Column<int>(type: "integer", nullable: false),
                    not_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    eligible_agent_ids = table.Column<List<string>>(type: "text[]", nullable: false),
                    queue_reason = table.Column<string>(type: "text", nullable: true),
                    agent_id = table.Column<string>(type: "text", nullable: true),
                    interface_name = table.Column<string>(type: "text", nullable: true),
                    tool_id = table.Column<string>(type: "text", nullable: true),
                    last_agent_id = table.Column<string>(type: "text", nullable: true),
                    lease_id = table.Column<Guid>(type: "uuid", nullable: true),
                    lease_expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    assigned_rate_per_second = table.Column<int>(type: "integer", nullable: true),
                    attempt = table.Column<int>(type: "integer", nullable: false),
                    max_attempts = table.Column<int>(type: "integer", nullable: false),
                    backoff_seconds = table.Column<int>(type: "integer", nullable: false),
                    next_attempt_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    cancel_requested = table.Column<bool>(type: "boolean", nullable: false),
                    progress_percent = table.Column<double>(type: "double precision", nullable: true),
                    progress_message = table.Column<string>(type: "text", nullable: true),
                    coverage_json = table.Column<string>(type: "jsonb", nullable: true),
                    error = table.Column<string>(type: "text", nullable: true),
                    failure_reason = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    duration_ms = table.Column<long>(type: "bigint", nullable: true),
                    tool_version = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    finished_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    payload_json = table.Column<string>(type: "jsonb", nullable: false),
                    xmin = table.Column<uint>(type: "xid", rowVersion: true, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_jobs", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "scan_limits",
                schema: "scanning",
                columns: table => new
                {
                    id = table.Column<int>(type: "integer", nullable: false),
                    values_json = table.Column<string>(type: "jsonb", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_limits", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "scan_runs",
                schema: "scanning",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    workflow_key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    workflow_version = table.Column<int>(type: "integer", nullable: false),
                    network_ids = table.Column<List<Guid>>(type: "uuid[]", nullable: false),
                    priority = table.Column<int>(type: "integer", nullable: false),
                    max_rate_per_second = table.Column<int>(type: "integer", nullable: true),
                    not_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    schedule_id = table.Column<Guid>(type: "uuid", nullable: true),
                    scheduled_fire_time = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    triggered_by = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    started_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    finished_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    coverage_complete = table.Column<bool>(type: "boolean", nullable: false),
                    message = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("pk_scan_runs", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "ix_result_batches_job_id_lease_id",
                schema: "scanning",
                table: "result_batches",
                columns: new[] { "job_id", "lease_id" });

            migrationBuilder.CreateIndex(
                name: "ix_result_batches_scan_run_id_step_id",
                schema: "scanning",
                table: "result_batches",
                columns: new[] { "scan_run_id", "step_id" });

            migrationBuilder.CreateIndex(
                name: "ix_scan_events_event_id",
                schema: "scanning",
                table: "scan_events",
                column: "event_id",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_scan_events_scan_run_id_seq",
                schema: "scanning",
                table: "scan_events",
                columns: new[] { "scan_run_id", "seq" });

            migrationBuilder.CreateIndex(
                name: "ix_scan_jobs_agent_id_status",
                schema: "scanning",
                table: "scan_jobs",
                columns: new[] { "agent_id", "status" });

            migrationBuilder.CreateIndex(
                name: "ix_scan_jobs_scan_run_id_status",
                schema: "scanning",
                table: "scan_jobs",
                columns: new[] { "scan_run_id", "status" });

            migrationBuilder.CreateIndex(
                name: "ix_scan_jobs_scan_run_id_step_id_target_key_perspective_key",
                schema: "scanning",
                table: "scan_jobs",
                columns: new[] { "scan_run_id", "step_id", "target_key", "perspective_key" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_scan_jobs_status_priority_created_at",
                schema: "scanning",
                table: "scan_jobs",
                columns: new[] { "status", "priority", "created_at" });

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_schedule_id_scheduled_fire_time",
                schema: "scanning",
                table: "scan_runs",
                columns: new[] { "schedule_id", "scheduled_fire_time" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "ix_scan_runs_status_created_at",
                schema: "scanning",
                table: "scan_runs",
                columns: new[] { "status", "created_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "job_performance",
                schema: "scanning");

            migrationBuilder.DropTable(
                name: "result_batches",
                schema: "scanning");

            migrationBuilder.DropTable(
                name: "scan_events",
                schema: "scanning");

            migrationBuilder.DropTable(
                name: "scan_jobs",
                schema: "scanning");

            migrationBuilder.DropTable(
                name: "scan_limits",
                schema: "scanning");

            migrationBuilder.DropTable(
                name: "scan_runs",
                schema: "scanning");
        }
    }
}
