using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Scanning.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TriageScanRunNotesTags : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "notes",
                schema: "scanning",
                table: "scan_runs",
                type: "character varying(4000)",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<List<string>>(
                name: "tags",
                schema: "scanning",
                table: "scan_runs",
                type: "text[]",
                nullable: false,
                defaultValueSql: "ARRAY[]::text[]"); // existing runs: no tags
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "notes",
                schema: "scanning",
                table: "scan_runs");

            migrationBuilder.DropColumn(
                name: "tags",
                schema: "scanning",
                table: "scan_runs");
        }
    }
}
