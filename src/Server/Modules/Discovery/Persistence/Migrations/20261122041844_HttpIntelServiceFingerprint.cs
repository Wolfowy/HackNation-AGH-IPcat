using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Discovery.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class HttpIntelServiceFingerprint : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Artifacts",
                schema: "discovery",
                table: "services",
                type: "jsonb",
                nullable: true,
                defaultValueSql: "'[]'::jsonb"); // existing services start without artifacts instead of a null collection

            migrationBuilder.AddColumn<string>(
                name: "DeviceProduct",
                schema: "discovery",
                table: "services",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeviceType",
                schema: "discovery",
                table: "services",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeviceVendor",
                schema: "discovery",
                table: "services",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "FingerprintRunId",
                schema: "discovery",
                table: "services",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HttpDetailsJson",
                schema: "discovery",
                table: "services",
                type: "jsonb",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Artifacts",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "DeviceProduct",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "DeviceType",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "DeviceVendor",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "FingerprintRunId",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "HttpDetailsJson",
                schema: "discovery",
                table: "services");
        }
    }
}
