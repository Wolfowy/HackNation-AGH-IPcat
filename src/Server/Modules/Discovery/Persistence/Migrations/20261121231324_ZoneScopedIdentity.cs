using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace WebScan.Server.Modules.Discovery.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class ZoneScopedIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_hosts_Address",
                schema: "discovery",
                table: "hosts");

            migrationBuilder.DropPrimaryKey(
                name: "PK_asset_annotations",
                schema: "discovery",
                table: "asset_annotations");

            migrationBuilder.DropIndex(
                name: "IX_asset_annotation_revisions_Address_ChangedAt",
                schema: "discovery",
                table: "asset_annotation_revisions");

            migrationBuilder.AddColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "signature_matches",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "services",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "CoverageByZone",
                schema: "discovery",
                table: "run_processing",
                type: "jsonb",
                nullable: true);

            // Asset identity becomes (zone, address); a missing zone is the default zone "".
            migrationBuilder.Sql("""
                UPDATE discovery.observations SET "Zone" = '' WHERE "Zone" IS NULL;
                UPDATE discovery.hosts SET "Zone" = '' WHERE "Zone" IS NULL;
                """);

            migrationBuilder.AlterColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "observations",
                type: "text",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AlterColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "hosts",
                type: "text",
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "text",
                oldNullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "change_events",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "asset_annotations",
                type: "text",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "asset_annotation_revisions",
                type: "text",
                nullable: false,
                defaultValue: "");

            // Hosts were unique by address until now, so every child row and annotation maps to exactly one host zone.
            migrationBuilder.Sql("""
                UPDATE discovery.services s SET "Zone" = h."Zone" FROM discovery.hosts h WHERE s."HostId" = h."Id";
                UPDATE discovery.signature_matches m SET "Zone" = h."Zone" FROM discovery.hosts h WHERE m."HostId" = h."Id";
                UPDATE discovery.change_events c SET "Zone" = h."Zone" FROM discovery.hosts h WHERE c."HostId" = h."Id";
                UPDATE discovery.asset_annotations a SET "Zone" = h."Zone" FROM discovery.hosts h WHERE a."Address" = h."Address";
                UPDATE discovery.asset_annotation_revisions r SET "Zone" = h."Zone" FROM discovery.hosts h WHERE r."Address" = h."Address";
                """);

            migrationBuilder.AddPrimaryKey(
                name: "PK_asset_annotations",
                schema: "discovery",
                table: "asset_annotations",
                columns: new[] { "Zone", "Address" });

            migrationBuilder.CreateIndex(
                name: "IX_hosts_Address",
                schema: "discovery",
                table: "hosts",
                column: "Address");

            migrationBuilder.CreateIndex(
                name: "IX_hosts_Zone_Address",
                schema: "discovery",
                table: "hosts",
                columns: new[] { "Zone", "Address" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_asset_annotation_revisions_Zone_Address_ChangedAt",
                schema: "discovery",
                table: "asset_annotation_revisions",
                columns: new[] { "Zone", "Address", "ChangedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_hosts_Address",
                schema: "discovery",
                table: "hosts");

            migrationBuilder.DropIndex(
                name: "IX_hosts_Zone_Address",
                schema: "discovery",
                table: "hosts");

            migrationBuilder.DropPrimaryKey(
                name: "PK_asset_annotations",
                schema: "discovery",
                table: "asset_annotations");

            migrationBuilder.DropIndex(
                name: "IX_asset_annotation_revisions_Zone_Address_ChangedAt",
                schema: "discovery",
                table: "asset_annotation_revisions");

            migrationBuilder.DropColumn(
                name: "Zone",
                schema: "discovery",
                table: "signature_matches");

            migrationBuilder.DropColumn(
                name: "Zone",
                schema: "discovery",
                table: "services");

            migrationBuilder.DropColumn(
                name: "CoverageByZone",
                schema: "discovery",
                table: "run_processing");

            migrationBuilder.DropColumn(
                name: "Zone",
                schema: "discovery",
                table: "change_events");

            migrationBuilder.DropColumn(
                name: "Zone",
                schema: "discovery",
                table: "asset_annotations");

            migrationBuilder.DropColumn(
                name: "Zone",
                schema: "discovery",
                table: "asset_annotation_revisions");

            migrationBuilder.AlterColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "observations",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AlterColumn<string>(
                name: "Zone",
                schema: "discovery",
                table: "hosts",
                type: "text",
                nullable: true,
                oldClrType: typeof(string),
                oldType: "text");

            migrationBuilder.AddPrimaryKey(
                name: "PK_asset_annotations",
                schema: "discovery",
                table: "asset_annotations",
                column: "Address");

            migrationBuilder.CreateIndex(
                name: "IX_hosts_Address",
                schema: "discovery",
                table: "hosts",
                column: "Address",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_asset_annotation_revisions_Address_ChangedAt",
                schema: "discovery",
                table: "asset_annotation_revisions",
                columns: new[] { "Address", "ChangedAt" });
        }
    }
}
