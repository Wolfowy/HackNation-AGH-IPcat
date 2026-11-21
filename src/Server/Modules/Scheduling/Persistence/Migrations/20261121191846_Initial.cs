using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Scheduling.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "scheduling");

            migrationBuilder.CreateTable(
                name: "schedules",
                schema: "scheduling",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CronExpression = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    TimeZone = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    WorkflowKey = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    WorkflowVersion = table.Column<int>(type: "integer", nullable: true),
                    NetworkIds = table.Column<List<Guid>>(type: "uuid[]", nullable: false),
                    Priority = table.Column<int>(type: "integer", nullable: false),
                    MaxRatePerSecond = table.Column<int>(type: "integer", nullable: true),
                    WindowDurationMinutes = table.Column<int>(type: "integer", nullable: true),
                    AllowedWindows = table.Column<string>(type: "jsonb", nullable: false),
                    OverlapPolicy = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    NextFireAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastFireAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LastRunId = table.Column<Guid>(type: "uuid", nullable: true),
                    QueuedFireTime = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_schedules", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_schedules_LastRunId",
                schema: "scheduling",
                table: "schedules",
                column: "LastRunId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "schedules",
                schema: "scheduling");
        }
    }
}
