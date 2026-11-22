using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Networks.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class NetworksScopePorts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<List<string>>(
                name: "AllowedPorts",
                schema: "networks",
                table: "scope_policy",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");

            migrationBuilder.AddColumn<List<string>>(
                name: "ExcludedPorts",
                schema: "networks",
                table: "scope_policy",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedPorts",
                schema: "networks",
                table: "scope_policy");

            migrationBuilder.DropColumn(
                name: "ExcludedPorts",
                schema: "networks",
                table: "scope_policy");
        }
    }
}
