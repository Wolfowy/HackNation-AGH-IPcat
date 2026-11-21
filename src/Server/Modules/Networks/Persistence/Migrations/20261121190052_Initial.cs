using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Networks.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "networks");

            migrationBuilder.CreateTable(
                name: "networks",
                schema: "networks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    Zone = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Ranges = table.Column<List<string>>(type: "text[]", nullable: false),
                    Exclusions = table.Column<List<string>>(type: "text[]", nullable: false),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    MaxRatePerSecond = table.Column<int>(type: "integer", nullable: true),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_networks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "scope_policy",
                schema: "networks",
                columns: table => new
                {
                    Id = table.Column<int>(type: "integer", nullable: false),
                    Allowed = table.Column<List<string>>(type: "text[]", nullable: false),
                    Excluded = table.Column<List<string>>(type: "text[]", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_scope_policy", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "zones",
                schema: "networks",
                columns: table => new
                {
                    Name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Description = table.Column<string>(type: "character varying(1000)", maxLength: 1000, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_zones", x => x.Name);
                });

            migrationBuilder.CreateIndex(
                name: "IX_networks_Name",
                schema: "networks",
                table: "networks",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_networks_Zone",
                schema: "networks",
                table: "networks",
                column: "Zone");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "networks",
                schema: "networks");

            migrationBuilder.DropTable(
                name: "scope_policy",
                schema: "networks");

            migrationBuilder.DropTable(
                name: "zones",
                schema: "networks");
        }
    }
}
