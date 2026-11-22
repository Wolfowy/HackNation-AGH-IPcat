#:project ../src/Server/Modules/Signatures/WebScan.Server.Modules.Signatures.csproj
#:property PublishAot=false

// Builds the curated "nuclei-safe" signature pack from a pinned nuclei-templates release (MIT, ProjectDiscovery).
// Run from the repository root:  dotnet run scripts/build-nuclei-safe-pack.cs
// Output: src/Server/Modules/Signatures/Packs/nuclei-safe/{pack.json, LICENSE.md, templates/*.yaml} (embedded and seeded at startup).
// Selection: directories below, product allowlist (template id tokens), info/low severity, no excluded tags, <= MaxRequests requests,
// GET/HEAD only, plus the server's own NucleiTemplateValidator. Each template gets the "pack-nuclei-safe" tag; the digest line is
// dropped because the content changes (nuclei treats the template as unsigned, which is fine for http templates).
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using WebScan.Server.Modules.Signatures.Persistence;
using WebScan.Server.Modules.Signatures.Validation;
using YamlDotNet.RepresentationModel;

const string Tag = "v10.5.2";
const string TarballSha256 = "016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574";
const string PackTag = "pack-nuclei-safe";
const int MaxRequests = 5;
var url = $"https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/{Tag}.tar.gz";
var output = args.Length > 0 ? args[0] : "src/Server/Modules/Signatures/Packs/nuclei-safe";

// Directory -> pack category. Products are matched against whole '-'-separated tokens of the template id; "iot" takes everything safe.
var directories = new Dictionary<string, string>
{
    ["http/technologies/"] = "technology",
    ["http/exposed-panels/"] = "panel",
    ["http/iot/"] = "iot",
    ["http/misconfiguration/installer/"] = "installer",
};
// kube-api lists pods/secrets of unauthenticated clusters (data access, not presence); c2 = malware panels; eol/plugins = too many.
string[] skippedSubdirectories =
[
    "http/technologies/wordpress/plugins/", "http/technologies/wordpress/themes/", "http/technologies/eol/",
    "http/technologies/kubernetes/kube-api/", "http/exposed-panels/c2/",
];
// Template id tokens that signal reading exposed data rather than detecting a product.
string[] excludedIdTokens = ["exposure", "exposed", "secrets", "enum", "disclosure", "leak", "dump", "debug", "listing"];

string[] products =
[
    // CMS, e-commerce, portals, forums
    "wordpress", "wp", "joomla", "drupal", "magento", "typo3", "prestashop", "opencart", "shopware", "woocommerce", "ghost", "umbraco",
    "sitecore", "liferay", "aem", "kentico", "dotnetnuke", "dnn", "concrete5", "craft", "craftcms", "contao", "modx", "silverstripe",
    "strapi", "directus", "wagtail", "plone", "mediawiki", "moodle", "phpbb", "vbulletin", "discourse", "xenforo", "mybb", "bitrix",
    "nopcommerce", "oscommerce", "dokuwiki", "bookstack", "wikijs",
    // web/app servers, proxies, frameworks
    "apache", "nginx", "iis", "tomcat", "jboss", "wildfly", "weblogic", "websphere", "glassfish", "jetty", "lighttpd", "caddy",
    "traefik", "haproxy", "envoy", "varnish", "openresty", "litespeed", "kong", "php", "aspnet", "asp", "laravel", "symfony", "django",
    "flask", "rails", "express", "spring", "springboot", "struts", "nextjs", "nuxt", "angular", "react", "vue", "codeigniter", "cakephp",
    "yii", "swagger", "openapi",
    // devops, repositories, CI/CD, containers
    "jenkins", "gitlab", "gitea", "gogs", "bitbucket", "teamcity", "bamboo", "drone", "argocd", "sonarqube", "nexus", "artifactory",
    "jfrog", "harbor", "portainer", "rancher", "kubernetes", "kube", "docker", "openshift", "nomad", "consul", "vault", "awx", "airflow",
    "jupyter", "mlflow", "minio",
    // monitoring, logging, data
    "grafana", "kibana", "elasticsearch", "opensearch", "prometheus", "zabbix", "nagios", "icinga", "splunk", "graylog", "netdata",
    "cacti", "prtg", "librenms", "observium", "uptime", "sentry", "metabase", "superset", "redash", "phpmyadmin", "adminer", "pgadmin",
    "phppgadmin", "mongo", "couchdb", "rabbitmq", "activemq", "kafka", "solr", "hadoop", "spark", "flink", "zeppelin", "neo4j",
    "influxdb", "clickhouse",
    // collaboration, business, identity
    "confluence", "jira", "sharepoint", "exchange", "owa", "outlook", "citrix", "netscaler", "nextcloud", "owncloud", "seafile",
    "roundcube", "zimbra", "horde", "squirrelmail", "rocketchat", "mattermost", "odoo", "sugarcrm", "vtiger", "suitecrm", "dolibarr",
    "redmine", "mantis", "bugzilla", "phabricator", "openproject", "glpi", "osticket", "zammad", "otrs", "manageengine", "solarwinds",
    "keycloak", "adfs", "openam", "authentik", "authelia", "freeipa",
    // hosting / virtualization / server management
    "cpanel", "whm", "plesk", "webmin", "usermin", "virtualmin", "directadmin", "ispconfig", "cyberpanel", "vesta", "hestia", "ajenti",
    "cockpit", "froxlor", "proxmox", "vmware", "vcenter", "esxi", "vsphere", "ovirt", "idrac", "ilo", "ipmi", "supermicro", "openstack",
    "veeam", "synology", "qnap", "truenas", "freenas", "unraid", "openmediavault",
    // network and security appliances, routers, VPN, remote access
    "fortinet", "fortigate", "fortiweb", "fortimail", "paloalto", "panos", "globalprotect", "sonicwall", "pulse", "ivanti", "f5", "bigip",
    "checkpoint", "sophos", "watchguard", "barracuda", "cisco", "juniper", "aruba", "meraki", "mikrotik", "routeros", "ubiquiti",
    "unifi", "tplink", "netgear", "dlink", "zyxel", "huawei", "openwrt", "luci", "pfsense", "opnsense", "ddwrt", "draytek", "linksys",
    "router", "openvpn", "pihole", "adguard", "guacamole", "meshcentral", "novnc",
    // IoT: cameras, NVR/VMS, printers, smart home
    "hikvision", "dahua", "axis", "avtech", "vivotek", "foscam", "reolink", "uniview", "mobotix", "geovision", "zoneminder", "frigate",
    "motioneye", "hp", "brother", "epson", "canon", "xerox", "kyocera", "ricoh", "lexmark", "konica", "cups", "octoprint", "homeassistant",
    "openhab", "nodered", "domoticz", "iobroker",
];

// Anything carrying one of these tags is not a passive presence check.
string[] excludedTags =
[
    "intrusive", "vuln", "unauth", "exposure", "default-login", "oast", "rce", "lfi", "rfi", "sqli", "xss", "ssrf", "ssti", "xxe", "dos",
    "fuzz", "fuzzing", "bruteforce", "brute-force", "cve", "kev", "exploit", "takeover", "traversal", "injection", "auth-bypass",
    "backdoor", "credential-stuffing", "creds-stuffing", "redirect", "disclosure", "c2", "malware", "honeypot",
];
string[] allowedTopLevel = ["id", "info", "http", "requests", "variables"];
string[] safeMethods = ["GET", "HEAD"];

using var http = new HttpClient();
http.DefaultRequestHeaders.UserAgent.ParseAdd("webscan-pack-builder");
Console.WriteLine($"Downloading {url}");
var tarball = await http.GetByteArrayAsync(url);
var actualSha = Convert.ToHexStringLower(SHA256.HashData(tarball));
if (actualSha != TarballSha256)
    throw new InvalidOperationException($"Tarball SHA-256 mismatch: expected {TarballSha256}, got {actualSha}. Update the pin only after reviewing the release.");

var files = new Dictionary<string, string>(StringComparer.Ordinal);
using (var reader = new TarReader(new GZipStream(new MemoryStream(tarball), CompressionMode.Decompress)))
{
    while (reader.GetNextEntry() is { } entry)
    {
        if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null) continue;
        var path = entry.Name[(entry.Name.IndexOf('/') + 1)..]; // strip "nuclei-templates-x.y.z/"
        if (path == "LICENSE.md" || (path.EndsWith(".yaml", StringComparison.Ordinal) && directories.Keys.Any(path.StartsWith)))
            files[path] = new StreamReader(entry.DataStream, Encoding.UTF8).ReadToEnd().ReplaceLineEndings("\n");
    }
}

var builtIn = BuiltInSignatures.All.Select(s => s.Id).ToHashSet(StringComparer.OrdinalIgnoreCase);
var selected = new SortedDictionary<string, (string Path, string Name, string Category, string Content)>(StringComparer.Ordinal);
var rejected = new Dictionary<string, int>();
void Reject(string reason) => rejected[reason] = rejected.GetValueOrDefault(reason) + 1;

foreach (var (path, original) in files.Where(f => f.Key != "LICENSE.md").OrderBy(f => f.Key, StringComparer.Ordinal))
{
    if (skippedSubdirectories.Any(path.StartsWith)) { Reject("skipped subdirectory"); continue; }
    var category = directories.First(d => path.StartsWith(d.Key, StringComparison.Ordinal)).Value;
    var tokens = Path.GetFileNameWithoutExtension(path).ToLowerInvariant().Split('-', '_', '.');
    if (category != "iot" && !products.Any(p => tokens.Contains(p))) { Reject("not in product allowlist"); continue; }
    if (tokens.Any(excludedIdTokens.Contains)) { Reject("exposure-style id"); continue; }

    YamlMappingNode root;
    try
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(original));
        root = (YamlMappingNode)stream.Documents.Single().RootNode;
    }
    catch (Exception) { Reject("unparseable"); continue; }

    var id = (root.Children.TryGetValue(new YamlScalarNode("id"), out var idNode) ? (idNode as YamlScalarNode)?.Value : null) ?? "";
    var keys = root.Children.Keys.Select(k => ((YamlScalarNode)k).Value!).ToList();
    if (keys.Any(k => !allowedTopLevel.Contains(k))) { Reject("non-http protocol/section"); continue; }
    var info = (YamlMappingNode)root.Children[new YamlScalarNode("info")];
    var severity = (info.Children.TryGetValue(new YamlScalarNode("severity"), out var sev) ? ((YamlScalarNode)sev).Value : null)?.Trim().ToLowerInvariant();
    if (severity is not ("info" or "low")) { Reject("severity above low"); continue; }
    if (!info.Children.TryGetValue(new YamlScalarNode("tags"), out var tagNode) || tagNode is not YamlScalarNode tagScalar) { Reject("no tags"); continue; }
    var tags = (tagScalar.Value ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(t => t.ToLowerInvariant()).ToList();
    if (tags.Any(excludedTags.Contains)) { Reject("excluded tag"); continue; }

    var requests = root.Children.Where(c => ((YamlScalarNode)c.Key).Value is "http" or "requests").SelectMany(c => ((YamlSequenceNode)c.Value).Children)
        .OfType<YamlMappingNode>().ToList();
    if (requests.Count == 0) { Reject("no http requests"); continue; }
    int Count(YamlMappingNode r, string key) => r.Children.TryGetValue(new YamlScalarNode(key), out var n) && n is YamlSequenceNode s ? s.Children.Count : 0;
    if (requests.Sum(r => Count(r, "path") + Count(r, "raw")) > MaxRequests) { Reject($"more than {MaxRequests} requests"); continue; }
    string? Scalar(YamlMappingNode r, string key) => r.Children.TryGetValue(new YamlScalarNode(key), out var n) ? (n as YamlScalarNode)?.Value : null;
    if (requests.Any(r => Count(r, "path") > 0 && !safeMethods.Contains((Scalar(r, "method") ?? "GET").ToUpperInvariant()))) { Reject("method other than GET/HEAD"); continue; }
    if (requests.Any(r => r.Children.Keys.Any(k => ((YamlScalarNode)k).Value is "body" or "self-contained"))) { Reject("request body / self-contained"); continue; }
    if (requests.SelectMany(r => r.Children.TryGetValue(new YamlScalarNode("raw"), out var raw) ? ((YamlSequenceNode)raw).Children : [])
        .Any(raw => !safeMethods.Contains(((YamlScalarNode)raw).Value!.TrimStart().Split(' ', 2)[0].ToUpperInvariant()))) { Reject("method other than GET/HEAD"); continue; }

    if (builtIn.Contains(id) || selected.ContainsKey(id)) { Reject("duplicate id"); continue; }

    // Tag the template for pack selection (signatureTags / nuclei -tags) and drop the now invalid signature digest.
    var tagLine = new Regex(@"(?m)^(  tags:[ \t]*)(.+?)[ \t]*$");
    if (tagLine.Matches(original).Count != 1) { Reject("ambiguous tags line"); continue; }
    var content = tagLine.Replace(original, m => $"{m.Groups[1].Value}{m.Groups[2].Value},{PackTag}");
    content = Regex.Replace(content, @"(?m)^# digest: .*\r?\n?", "").TrimEnd() + "\n";

    var validation = NucleiTemplateValidator.Validate(content);
    if (!validation.Valid || validation.TemplateId != id || !validation.Tags.Contains(PackTag)) { Reject("server validator"); continue; }
    var name = ((YamlScalarNode)info.Children[new YamlScalarNode("name")]).Value!;
    selected[id] = (path, name, category, content);
}

var templatesDir = Path.Combine(output, "templates");
if (Directory.Exists(templatesDir)) Directory.Delete(templatesDir, recursive: true);
Directory.CreateDirectory(templatesDir);
foreach (var (id, t) in selected) File.WriteAllText(Path.Combine(templatesDir, id + ".yaml"), t.Content, new UTF8Encoding(false));
File.WriteAllText(Path.Combine(output, "LICENSE.md"), files["LICENSE.md"], new UTF8Encoding(false));

var manifest = new
{
    name = "nuclei-safe",
    version = Tag,
    tag = PackTag,
    source = url,
    sourceSha256 = TarballSha256,
    license = "MIT",
    attribution = "Templates by ProjectDiscovery, Inc. and the nuclei-templates contributors (https://github.com/projectdiscovery/nuclei-templates), MIT License (see LICENSE.md). Modified: pack tag added, signature digest removed.",
    generator = "scripts/build-nuclei-safe-pack.cs",
    counts = selected.Values.GroupBy(t => t.Category).OrderBy(g => g.Key).ToDictionary(g => g.Key, g => g.Count()),
    templates = selected.Select(t => new { id = t.Key, name = t.Value.Name, category = t.Value.Category, path = t.Value.Path }),
};
File.WriteAllText(Path.Combine(output, "pack.json"), JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }) + "\n");

Console.WriteLine($"Selected {selected.Count} templates ({string.Join(", ", manifest.counts.Select(c => $"{c.Key}: {c.Value}"))}), " +
    $"{selected.Values.Sum(t => Encoding.UTF8.GetByteCount(t.Content)) / 1024} KiB.");
foreach (var (reason, count) in rejected.OrderByDescending(r => r.Value)) Console.WriteLine($"  rejected {count,5}: {reason}");
