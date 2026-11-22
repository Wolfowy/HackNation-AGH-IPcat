using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Discovery.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class TriageFindingTriageAndServiceAnnotations : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Notes",
                schema: "discovery",
                table: "signature_matches",
                type: "character varying(4000)",
                maxLength: 4000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SeverityOverride",
                schema: "discovery",
                table: "signature_matches",
                type: "character varying(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Triage",
                schema: "discovery",
                table: "signature_matches",
                type: "character varying(32)",
                maxLength: 32,
                nullable: false,
                defaultValue: "None"); // existing findings: untriaged

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "TriagedAt",
                schema: "discovery",
                table: "signature_matches",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TriagedBy",
                schema: "discovery",
                table: "signature_matches",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<List<string>>(
                name: "UserTags",
                schema: "discovery",
                table: "signature_matches",
                type: "text[]",
                nullable: false,
                defaultValueSql: "ARRAY[]::text[]");

            migrationBuilder.CreateTable(
                name: "service_annotations",
                schema: "discovery",
                columns: table => new
                {
                    Zone = table.Column<string>(type: "text", nullable: false),
                    Address = table.Column<string>(type: "text", nullable: false),
                    Port = table.Column<int>(type: "integer", nullable: false),
                    Transport = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Notes = table.Column<string>(type: "text", nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    Criticality = table.Column<string>(type: "text", nullable: true),
                    Owner = table.Column<string>(type: "text", nullable: true),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedBy = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_service_annotations", x => new { x.Zone, x.Address, x.Port, x.Transport });
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "service_annotations",
                schema: "discovery");

            migrationBuilder.DropColumn(
                name: "Notes",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "SeverityOverride",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "Triage",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "TriagedAt",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "TriagedBy",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "UserTags",
                schema: "discovery",
                table: "signature_matches");
        }
    }
}
