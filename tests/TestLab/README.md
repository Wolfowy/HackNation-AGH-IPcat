# WebScan TestLab

A small, isolated set of deliberately simple targets for **authorized local testing only**: verifying the agent's
tool manifests, capturing real tool output for parser tests, and end-to-end scans. Never point WebScan at systems you
are not explicitly authorized to scan; the lab exists so nothing outside your own machine is touched.

## Targets (network `webscan-lab`, bridge, `172.30.0.0/24`)

| Address | Service | Purpose |
|---|---|---|
| 172.30.0.10:80 | nginx | plain web server |
| 172.30.0.11:80 | Apache httpd | second web server / technology |
| 172.30.0.12:8080, :8443 | ASP.NET Core app (`apps/webapp`) | HTTP + HTTPS with a self-signed certificate generated at startup (CN `testlab-webapp.local`), `Set-Cookie` for masking tests, `/old` → `/` redirect |
| 172.30.0.13:80 | "admin panel" (nginx + `apps/admin-panel`) | title `WebScan TestLab Admin Panel`, login form, favicon; matched by `signatures/webscan-testlab-admin-panel.yaml` |
| 172.30.0.14:2323 | TCP banner (busybox `nc`) | prints `WEBSCAN-TESTLAB-BANNER v1.0` |
| 172.30.0.15:8081 | nginx, profile `change` | started only on demand to introduce a deliberate change between two scans |

`172.30.0.1` (gateway) and the address of any scanner container attached to the network also answer.

## Usage

```bash
docker compose -f tests/TestLab/docker-compose.yml up -d --build          # start the lab
docker compose -f tests/TestLab/docker-compose.yml --profile change up -d # add the "change" service (172.30.0.15:8081)
docker compose -f tests/TestLab/docker-compose.yml stop change            # remove the change again
docker compose -f tests/TestLab/docker-compose.yml --profile change down  # tear everything down
```

## Running the agent image against the lab

Build the agent image (context = repository root) and attach it to the lab network:

```bash
docker build -f src/Agent/Worker/Dockerfile -t webscan-agent:dev .
docker run --rm --network webscan-lab webscan-agent:dev --list-tools          # tools detected from tools.d
docker run --rm --network webscan-lab -e Agent__ServerUrl=https://<server> \
  -e Agent__EnrollmentToken=<token> webscan-agent:dev                         # regular agent
```

The image runs as the non-root user `webscan` (uid 10001); `nmap` and `naabu` carry `cap_net_raw` so SYN scans work
with Docker's default capabilities (add `--cap-add NET_RAW` on runtimes that drop it).

The `toolbox` target contains only the runtime and the scanning tools, which is handy for running tools by hand:

```bash
docker build -f src/Agent/Worker/Dockerfile --target toolbox -t webscan-agent-toolbox:dev .
docker run --rm --network webscan-lab -v "$PWD/tests/TestLab/signatures:/templates:ro" webscan-agent-toolbox:dev \
  nuclei -u http://172.30.0.13 -t /templates -jsonl -silent -disable-update-check -no-interactsh
```

## How the parser fixtures were captured

`tests/UnitTests/WebScan.Agent.UnitTests/Fixtures/*` are unedited outputs of real runs from the `toolbox` image inside
the lab network (nmap 7.93, naabu 2.7.0, httpx 1.12.0, nuclei 3.11.1, tlsx 1.5.0), using exactly the argv of the
manifests in `src/Agent/Worker/tools.d` with placeholders filled in (`{rate}`=100, `{parallelism}`=10, operation
parameter defaults, `HOME` set to an empty directory as the agent does):

| Fixture | Run |
|---|---|
| `nmap-host-discovery.xml` | host-discovery on `172.30.0.0/28` |
| `nmap-port-scan.xml` | port-scan of .10–.15, `ports=22,80,443,2323,8080,8081,8443` |
| `nmap-service-detection.xml` | service-detection (`-sV --script banner`) on the open endpoints |
| `nmap-tls.xml` | tls-probe (`--script ssl-cert`) on 172.30.0.12:8443 |
| `naabu.jsonl` | connect port-scan, same hosts/ports as nmap |
| `httpx.jsonl` | http-probe of all web endpoints, `paths=/,/old` (redirect chain), tech/favicon/TLS |
| `nuclei.jsonl` | signature-scan with only `signatures/` (no public templates are downloaded; also verified on a network without internet access) |
| `tlsx.jsonl` | tls-probe of 172.30.0.12:8443 and :8080 (non-TLS endpoint yields no line) |
| `versions.txt` | raw output of every manifest `versionArgs` command |

Re-capture after changing a manifest's arguments and keep fixtures unedited.
