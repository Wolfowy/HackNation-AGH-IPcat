using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace WebScan.Server.Modules.Signatures.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.EnsureSchema(
                name: "signatures");

            migrationBuilder.CreateTable(
                name: "signatures",
                schema: "signatures",
                columns: table => new
                {
                    Id = table.Column<string>(type: "character varying(100)", maxLength: 100, nullable: false),
                    Name = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    Severity = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    LatestVersion = table.Column<int>(type: "integer", nullable: false),
                    ApprovedVersion = table.Column<int>(type: "integer", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_signatures", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "signature_versions",
                schema: "signatures",
                columns: table => new
                {
                    SignatureId = table.Column<string>(type: "character varying(100)", nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    Content = table.Column<string>(type: "text", nullable: false),
                    Sha256 = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Severity = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: true),
                    Tags = table.Column<List<string>>(type: "text[]", nullable: false),
                    RequiresApprovalNote = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ApprovedBy = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    ApprovedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ApprovalNote = table.Column<string>(type: "character varying(2000)", maxLength: 2000, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_signature_versions", x => new { x.SignatureId, x.Version });
                    table.ForeignKey(
                        name: "FK_signature_versions_signatures_SignatureId",
                        column: x => x.SignatureId,
                        principalSchema: "signatures",
                        principalTable: "signatures",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.InsertData(
                schema: "signatures",
                table: "signatures",
                columns: new[] { "Id", "ApprovedVersion", "CreatedAt", "Kind", "LatestVersion", "Name", "Severity", "Status", "Tags", "UpdatedAt" },
                values: new object[,]
                {
                    { "admin-panel", 1, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "ClassificationRule", 1, "Administration panel", "info", "Approved", new List<string> { "classification" }, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { "apache-http-server", 1, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "ClassificationRule", 1, "Apache HTTP Server", "info", "Approved", new List<string> { "tech", "web-server" }, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { "nginx-default-page", 1, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "NucleiTemplate", 1, "Nginx default welcome page", "info", "Approved", new List<string> { "tech", "nginx", "misconfig" }, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { "nginx-web-server", 1, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "ClassificationRule", 1, "nginx web server", "info", "Approved", new List<string> { "tech", "web-server" }, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) },
                    { "sensitive-port-exposed", 1, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "ChangeRule", 1, "Sensitive service port newly exposed", "medium", "Approved", new List<string> { "exposure" }, new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)) }
                });

            migrationBuilder.InsertData(
                schema: "signatures",
                table: "signature_versions",
                columns: new[] { "SignatureId", "Version", "ApprovalNote", "ApprovedAt", "ApprovedBy", "Content", "CreatedAt", "CreatedBy", "RequiresApprovalNote", "Severity", "Sha256", "Tags" },
                values: new object[,]
                {
                    { "admin-panel", 1, "Built-in signature", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", "{\n  \"description\": \"Classifies HTTP endpoints whose page title mentions an administration interface.\",\n  \"when\": { \"all\": [\n    { \"field\": \"kind\", \"operator\": \"Equals\", \"values\": [\"HttpResponse\"] },\n    { \"field\": \"http.title\", \"operator\": \"Contains\", \"values\": [\"admin\"] }\n  ] },\n  \"outcome\": { \"classificationTag\": \"admin-panel\", \"confidence\": 0.6 },\n  \"tags\": [\"classification\"]\n}", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", false, "info", "b96dccaf376529725b074296cde538540fd6c010c7a29916dc3889158b56bb5e", new List<string> { "classification" } },
                    { "apache-http-server", 1, "Built-in signature", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", "{\n  \"description\": \"Identifies Apache httpd from the detected service product or the HTTP Server header.\",\n  \"when\": { \"any\": [\n    { \"field\": \"service.product\", \"operator\": \"Contains\", \"values\": [\"apache httpd\"] },\n    { \"field\": \"http.webServer\", \"operator\": \"Equals\", \"values\": [\"Apache\"] },\n    { \"field\": \"http.webServer\", \"operator\": \"StartsWith\", \"values\": [\"Apache/\"] }\n  ] },\n  \"outcome\": { \"technology\": { \"name\": \"Apache HTTP Server\", \"versionField\": \"service.version\", \"category\": \"web-server\" }, \"confidence\": 0.9 },\n  \"tags\": [\"tech\", \"web-server\"]\n}", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", false, "info", "af010ffa5061e89a36e7edf5d4f12d173c3a735c6cc8c78c55b76ae1610faebd", new List<string> { "tech", "web-server" } },
                    { "nginx-default-page", 1, "Built-in signature", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", "id: nginx-default-page\ninfo:\n  name: Nginx Default Welcome Page\n  author: webscan\n  severity: info\n  description: Detects the default nginx welcome page, indicating an unconfigured web server.\n  tags: tech,nginx,misconfig\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/\"\n    matchers-condition: and\n    matchers:\n      - type: word\n        part: body\n        words:\n          - \"<title>Welcome to nginx!</title>\"\n      - type: status\n        status:\n          - 200", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", false, "info", "f67b4f241c4e91cd3d13cf209c1886d69374a32542fd1a157ffc730a418e36c3", new List<string> { "tech", "nginx", "misconfig" } },
                    { "nginx-web-server", 1, "Built-in signature", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", "{\n  \"description\": \"Identifies nginx from the detected service product or the HTTP Server header.\",\n  \"when\": { \"any\": [\n    { \"field\": \"service.product\", \"operator\": \"Contains\", \"values\": [\"nginx\"] },\n    { \"field\": \"http.webServer\", \"operator\": \"Contains\", \"values\": [\"nginx\"] }\n  ] },\n  \"outcome\": { \"technology\": { \"name\": \"nginx\", \"versionField\": \"service.version\", \"category\": \"web-server\" }, \"confidence\": 0.9 },\n  \"tags\": [\"tech\", \"web-server\"]\n}", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", false, "info", "a5da73d08c43d420e1f920beff386d201708fc96c3dc9c72c2490e867789bb28", new List<string> { "tech", "web-server" } },
                    { "sensitive-port-exposed", 1, "Built-in signature", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", "{\n  \"description\": \"Raises newly opened remote-access / database ports to medium severity.\",\n  \"changeTypes\": [\"NewPort\"],\n  \"when\": { \"field\": \"port\", \"operator\": \"In\", \"values\": [\"21\", \"23\", \"445\", \"1433\", \"3306\", \"3389\", \"5432\", \"5900\", \"6379\", \"9200\", \"27017\"] },\n  \"severity\": \"medium\",\n  \"tags\": [\"exposure\"]\n}", new DateTimeOffset(new DateTime(2026, 11, 1, 0, 0, 0, 0, DateTimeKind.Unspecified), new TimeSpan(0, 0, 0, 0, 0)), "system", false, "medium", "60a511937bd77a659137cf0f97481911f40052925fd4ee290ed32b027798b13b", new List<string> { "exposure" } }
                });

            migrationBuilder.CreateIndex(
                name: "IX_signatures_Kind_Status",
                schema: "signatures",
                table: "signatures",
                columns: new[] { "Kind", "Status" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "signature_versions",
                schema: "signatures");

            migrationBuilder.DropTable(
                name: "signatures",
                schema: "signatures");
        }
    }
}
