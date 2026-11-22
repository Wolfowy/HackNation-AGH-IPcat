# Signatures: rule language and shipped packs

Signatures detect the **presence** of a product, panel or environment. They never log in, send payloads or exploit anything.
Three kinds exist (see ARCHITECTURE.md §10): **Nuclei templates** (active, executed by agents, GET/HEAD only), **classification rules**
(passive JSON over stored observations, no extra traffic) and **change rules** (raise the severity of change events). Only the
approved version of a signature is executed or applied; retired signatures are ignored.

## 1. Classification rule format

```json
{
  "description": "Jenkins by its X-Jenkins header (value = version).",
  "when": { "field": "http.header.X-Jenkins", "operator": "Exists" },
  "outcome": {
    "technology": { "name": "Jenkins", "versionField": "http.header.X-Jenkins", "category": "ci-cd" },
    "classificationTag": "admin-panel",
    "confidence": 0.95
  },
  "tags": ["custom"]
}
```

* `when` is a condition tree: a leaf `{field, operator, values}` or `{all: [...]}`, `{any: [...]}`, `{not: {...}}` (max depth 8).
* `outcome` needs a `technology` and/or a `classificationTag` (`^[a-z0-9][a-z0-9_-]{0,63}$`). `technology.versionField` copies a field
  value as the version (use fields whose value *is* the version, e.g. `X-Jenkins`, `kbn-version`, `X-AspNet-Version`).
  `confidence` is 0–1 (default 0.8).
* Discovery evaluates every approved rule against every observation of a run (after PersistObservations). A match stores an info
  finding (source `classification-rule`) with evidence `field=value` for the fields the rule tested, the classification tag on the
  host/service and the technology with the rule's confidence.

### Operators and values

| Operator | Values | Matches when |
|---|---|---|
| `Exists` / `NotExists` | none | the field has a (non-empty) value / has none |
| `Equals` / `NotEquals` | exactly 1 | value equals (case-insensitive; numeric fields compare as numbers) / does not |
| `In` / `NotIn` | 1 or more | value equals any of the values / none of them |
| `Contains` / `StartsWith` | 1 or more | value contains / starts with **any** of the values (case-insensitive) |
| `GreaterThan` / `LessThan` | exactly 1 | numeric fields only (`port`, `http.statusCode`, `confidence.score`) |

A missing field never matches a positive operator and always matches `NotEquals` / `NotIn` / `NotExists`.

### List fields

`http.cookieNames`, `http.redirectChain`, `http.technologies` and `tls.subjectAlternativeNames` hold several values.
A leaf matches when **any element** matches (`Equals`, `In`, `Contains`, `StartsWith`); `NotEquals` / `NotIn` match when **no element**
matches; `Exists` = at least one element, `NotExists` = empty list. Example: `{"field": "http.cookieNames", "operator": "NotIn",
"values": ["PHPSESSID"]}` is true only if no cookie is called `PHPSESSID`.

### Field reference

| Field | Source (`DiscoveryObservation`) | Type |
|---|---|---|
| `kind` | observation kind (`HttpResponse`, `TlsCertificate`, `Service`, …) | enum |
| `address`, `hostname`, `port`, `transport` | target | text / numeric (`port`) |
| `source.toolId`, `host.status`, `port.state` | tool, host, port details | text |
| `service.name`, `service.product`, `service.version`, `service.tunnel` | service detection | text |
| `service.banner` | raw service banner (masked, max 1024 chars) | text |
| `http.url` | probed URL (incl. path) | text |
| `http.scheme`, `http.statusCode`, `http.title`, `http.webServer` | HTTP probe | text / numeric (`statusCode`) |
| `http.contentType`, `http.finalUrl`, `http.faviconHash` (Shodan mmh3) | HTTP probe | text |
| `http.header.<Name>` | response header `<Name>`, case-insensitive; `<Name>` = RFC 7230 token, 1–100 chars | text |
| `http.cookieNames` | cookie **names** (values are never stored) | list |
| `http.redirectChain`, `http.technologies` | redirect URLs, probe-reported technologies (`Name:version`) | list |
| `tls.subjectCommonName`, `tls.issuer` | certificate | text |
| `tls.subjectAlternativeNames` | certificate SANs | list |
| `technology.name`, `technology.category` | Technology observations | text |
| `signature.signatureId`, `signature.severity`, `confidence.score` | signature matches, confidence | text / numeric |

The same fields are available in workflow conditions (step `input.filter` and `when`, condition builder in the editor: pick
`http.header.<Name>` and type the header name). Change rules only see `address`, `hostname`, `port`, `transport`, `service.*` and
`technology.*` (change events carry no HTTP data). Header values are masked like stored headers (cookie values and tokens), so test
cookie *names* with `http.cookieNames`, not the `Set-Cookie` header.

## 2. Safe signature examples

| Goal | How |
|---|---|
| Specific header present | `{"field": "http.header.X-Jenkins", "operator": "Exists"}` |
| Specific cookie name | `{"field": "http.cookieNames", "operator": "In", "values": ["phpMyAdmin", "pma_lang"]}` |
| Favicon hash | `{"field": "http.faviconHash", "operator": "In", "values": ["81586312"]}` (Jenkins) |
| CMS fingerprint | WordPress: `{"any": [{"field": "http.cookieNames", "operator": "StartsWith", "values": ["wordpress_", "wp-settings-"]}, {"field": "http.header.Link", "operator": "Contains", "values": ["api.w.org"]}]}` |
| Staging / test environment | `{"field": "hostname", "operator": "StartsWith", "values": ["dev.", "test.", "staging.", "uat."]}` or the same on `tls.subjectAlternativeNames` |
| Login / admin path reached by redirect | `{"field": "http.redirectChain", "operator": "Contains", "values": ["/login", "/admin"]}` |
| IoT device by server header | `{"field": "http.webServer", "operator": "StartsWith", "values": ["App-webs", "Hikvision-Webs"]}` |
| Version from a header | outcome `"technology": {"name": "ASP.NET", "versionField": "http.header.X-AspNet-Version"}` |
| Characteristic HTML fragment, paths like `/login` `/admin` `/version`, version in a page footer | bodies are not stored, so use a Nuclei template (GET only, no credentials): |

```yaml
id: acme-admin-panel
info:
  name: ACME admin panel
  author: you
  severity: info
  tags: panel,acme
http:
  - method: GET
    path:
      - "{{BaseURL}}/admin/"
      - "{{BaseURL}}/version"
    stop-at-first-match: true
    matchers:
      - type: word
        part: body
        words: ["<div id=\"acme-login\">"]
    extractors:
      - type: regex
        group: 1
        regex: ["ACME Server v([0-9.]+)"]   # version in the footer
```

The Nuclei validator rejects `code`/`headless`/`javascript`/`file`/`workflow`/`flow` sections, `payloads`/`fuzzing`/`attack`,
methods other than GET/HEAD/OPTIONS, interactsh/OAST and intrusive tags (`intrusive`, `dos`, `fuzz`, `rce`, `sqli`, `xss`, `lfi`,
`default-login`, `bruteforce`, …).

## 3. Shipped packs

Packs live in `src/Server/Modules/Signatures/Packs/<name>/` (embedded into the server) and are applied at startup by
`SignaturePackSeeder`:

* new pack signatures are created **Approved** (author `pack:<name>`, approval note `Signature pack <name> <version>`);
* changed pack content becomes a new approved version; re-running with unchanged content does nothing (idempotent);
* signatures that disappear from the pack are retired;
* a signature an administrator **retired** or **edited** (latest version not written by the pack) is never touched again; ids that
  already belong to another signature are skipped; pack entries failing validation are skipped and logged.

To disable a pack signature, retire it (`POST /api/signatures/{id}/retire`). Every pack signature carries its pack tag.

### `webscan-default` (tag `pack-webscan-default`) — 38 passive classification rules

* **Environment**: `staging-environment` from host name / TLS CN / SAN labels (`dev|test|stage|staging|uat|qa|preprod|sandbox`,
  confidence 0.8) and from titles / `X-Environment` / `X-Env` headers (0.6); `debug-mode` from profiler headers (`X-Debug-Token`,
  `phpdebugbar-id`, `X-SourceFiles`).
* **Panels**: `login-page` (titles, `/login` URLs and redirects), `admin-panel` (`/admin`-style paths, known favicons), phpMyAdmin,
  Adminer, Tomcat Manager (Basic realm), Jenkins (+version), Grafana, Kibana (+version), Webmin, cPanel/WHM, Plesk, Portainer,
  Exchange OWA (+build), router admin interfaces (`network-device`).
* **IoT / devices**: MikroTik (title, banner), Ubiquiti, embedded web servers (GoAhead, Boa, mini_httpd, …), Hikvision, Dahua, Axis,
  generic IP cameras (`iot-camera`), printers (HP, Brother, Epson, Canon, Xerox, Kyocera, Ricoh, Lexmark, IPP/JetDirect →
  `iot-printer`), Synology and QNAP (`nas`).
* **CMS / technology**: WordPress, Drupal, Joomla, Magento (`cms`), PHP, ASP.NET (+version), Java servlet, SharePoint (+version),
  Atlassian.

### `nuclei-safe` (tag `pack-nuclei-safe`) — curated nuclei-templates

* Source: [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) **v10.5.2**, MIT License
  (`Packs/nuclei-safe/LICENSE.md`, attribution in `pack.json`). Content is modified only by adding the `pack-nuclei-safe` tag and
  removing the signature digest line (templates run as unsigned HTTP templates).
* Contents (`pack.json` lists every template with its upstream path): ~510 templates — 305 exposed panels, 156 technology
  detections, 49 IoT detections — about 440 KiB.
* Selection (`scripts/build-nuclei-safe-pack.cs`): directories `http/technologies`, `http/exposed-panels`, `http/iot`,
  `http/misconfiguration/installer` (minus WordPress plugins/themes, EOL, kube-api data listings and C2 panels); template id must name
  a product of the allowlist in the script (CMS, app servers, DevOps, monitoring, hosting panels, appliances, routers, cameras,
  printers, NAS…; IoT takes everything that passes); severity info/low; no excluded tag (`intrusive`, `vuln`, `unauth`, `exposure`,
  `default-login`, `oast`, `rce`, `lfi`, `sqli`, `xss`, `dos`, `fuzz`, `bruteforce`, `cve`, `takeover`, …); no exposure-style ids
  (`exposure`, `secrets`, `enum`, …); only `id`/`info`/`http`/`variables` sections; at most 5 requests; GET/HEAD only; no request
  body or `self-contained`; must pass the server's `NucleiTemplateValidator`.
* Regenerate (from the repository root; downloads the pinned tarball and checks its SHA-256):

  ```
  dotnet run scripts/build-nuclei-safe-pack.cs
  ```

  To move to a newer release, change `Tag` and `TarballSha256` in the script after reviewing the release, run it, review the diff
  and run the tests (`SignaturePackContentTests` re-validates every template). On the next start the seeder adds new versions,
  creates new templates and retires dropped ones.

### Recommended `ExecuteSignatures` parameters

Each `ExecuteSignatures` job carries its signature bundle inline, and nuclei runs every template of the bundle against every endpoint.
With no `signatureTags` the bundle contains all approved templates (the whole pack ≈ 0.5 MB, ~1–5 requests per template and
endpoint). Narrow it per workflow step:

| Use | Parameters |
|---|---|
| Everything safe (default severities) | `severities=info,low` |
| Only the curated pack | `signatureTags=pack-nuclei-safe`, `severities=info,low` |
| Technology / CMS fingerprinting | `signatureTags=tech` |
| Login and admin panels | `signatureTags=panel` |
| IoT devices | `signatureTags=iot` |
| Own templates only | give them a tag, e.g. `signatureTags=custom` |

`signatureTags` filters the bundle on the server and is also passed to nuclei as `-tags`, so a tag must appear in the template's
`info.tags`.
