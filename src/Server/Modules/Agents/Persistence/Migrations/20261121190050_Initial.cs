using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Agents.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "agents");

            migrationBuilder.CreateTable(
                name: "agents",
                schema: "agents",
                columns: table => new
                {
                    AgentId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Hostname = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    OsPlatform = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    OsDescription = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    AgentVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    RegisteredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastRegisteredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    LastHeartbeatAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    IsOnline = table.Column<bool>(type: "boolean", nullable: false),
                    Inventory = table.Column<string>(type: "jsonb", nullable: false),
                    InventoryHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    DeclaredZones = table.Column<List<string>>(type: "text[]", nullable: false),
                    AuthorizedZones = table.Column<List<string>>(type: "text[]", nullable: false),
                    AuthorizedNetworkIds = table.Column<List<Guid>>(type: "uuid[]", nullable: false),
                    ReportedMaxConcurrentJobs = table.Column<int>(type: "integer", nullable: false),
                    ReportedMaxRatePerSecond = table.Column<int>(type: "integer", nullable: false),
                    MaxConcurrentJobsOverride = table.Column<int>(type: "integer", nullable: true),
                    MaxRatePerSecondOverride = table.Column<int>(type: "integer", nullable: true),
                    Load = table.Column<string>(type: "jsonb", nullable: true),
                    SecretHash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    PreviousSecretHash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: true),
                    PreviousSecretValidUntil = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RotateRequested = table.Column<bool>(type: "boolean", nullable: false),
                    EnrollmentTokenId = table.Column<Guid>(type: "uuid", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_agents", x => x.AgentId);
                });

            migrationBuilder.CreateTable(
                name: "enrollment_tokens",
                schema: "agents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    TokenHash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    MaxUses = table.Column<int>(type: "integer", nullable: false),
                    Uses = table.Column<int>(type: "integer", nullable: false),
                    AutoApprove = table.Column<bool>(type: "boolean", nullable: false),
                    Zones = table.Column<List<string>>(type: "text[]", nullable: false),
                    Revoked = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_enrollment_tokens", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "tool_catalog",
                schema: "agents",
                columns: table => new
                {
                    ToolId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Approved = table.Column<bool>(type: "boolean", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    Capabilities = table.Column<List<string>>(type: "text[]", nullable: false),
                    Versions = table.Column<List<string>>(type: "text[]", nullable: false),
                    FirstSeenAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_tool_catalog", x => x.ToolId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_agents_Status",
                schema: "agents",
                table: "agents",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_enrollment_tokens_TokenHash",
                schema: "agents",
                table: "enrollment_tokens",
                column: "TokenHash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "agents",
                schema: "agents");

            migrationBuilder.DropTable(
                name: "enrollment_tokens",
                schema: "agents");

            migrationBuilder.DropTable(
                name: "tool_catalog",
                schema: "agents");
        }
    }
}
