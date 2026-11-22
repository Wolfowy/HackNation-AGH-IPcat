using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Scanning.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class JobToolRequirements : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "needs_raw_sockets",
                schema: "scanning",
                table: "scan_jobs",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<List<string>>(
                name: "required_parameters",
                schema: "scanning",
                table: "scan_jobs",
                type: "text[]",
                nullable: false,
                defaultValueSql: "ARRAY[]::text[]"); // existing jobs: no explicit parameters
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "needs_raw_sockets",
                schema: "scanning",
                table: "scan_jobs");

            migrationBuilder.DropColumn(
                name: "required_parameters",
                schema: "scanning",
                table: "scan_jobs");
        }
    }
}
