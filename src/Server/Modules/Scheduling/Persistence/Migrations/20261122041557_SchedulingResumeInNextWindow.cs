using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Scheduling.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class SchedulingResumeInNextWindow : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ResumeAt",
                schema: "scheduling",
                table: "schedules",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ResumeInNextWindow",
                schema: "scheduling",
                table: "schedules",
                type: "boolean",
                nullable: false,
                defaultValue: true); // existing schedules get the new default (resume on)

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ResumedWindowEnd",
                schema: "scheduling",
                table: "schedules",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ResumeAt",
                schema: "scheduling",
                table: "schedules");

            migrationBuilder.DropColumn(
                name: "ResumeInNextWindow",
                schema: "scheduling",
                table: "schedules");

            migrationBuilder.DropColumn(
                name: "ResumedWindowEnd",
                schema: "scheduling",
                table: "schedules");
        }
    }
}
