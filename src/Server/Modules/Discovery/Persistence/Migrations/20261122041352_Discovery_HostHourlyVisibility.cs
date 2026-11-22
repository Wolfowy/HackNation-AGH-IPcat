using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Discovery.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Discovery_HostHourlyVisibility : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<List<int>>(
                name: "HourlyMissed",
                schema: "discovery",
                table: "hosts",
                type: "integer[]",
                nullable: false,
                defaultValueSql: "'{}'"); // existing hosts start without hourly history

            migrationBuilder.AddColumn<List<int>>(
                name: "HourlySeen",
                schema: "discovery",
                table: "hosts",
                type: "integer[]",
                nullable: false,
                defaultValueSql: "'{}'"); // existing hosts start without hourly history
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "HourlyMissed",
                schema: "discovery",
                table: "hosts");

            migrationBuilder.DropColumn(
                name: "HourlySeen",
                schema: "discovery",
                table: "hosts");
        }
    }
}
