# Uruchomienie i testy

Wymagania: .NET SDK 10, Node 22+ / npm 10+, Docker z Compose v2 (wystarczy 20.10 / Compose 2.15).
Budowa obrazów (serwer, agent z narzędziami, frontend, TestLab) potrzebuje ok. 15–20 GB wolnego miejsca w VM Dockera;
przy braku miejsca PostgreSQL/RabbitMQ zatrzymują się z `No space left on device` (`docker system df`, `docker builder prune`).

## 1. Pełny stos w Docker Compose (z siecią testową)

```bash
cp deploy/docker/.env.example deploy/docker/.env      # zmień wszystkie sekrety!
(cd deploy/docker/certs && sh generate-certs.sh)      # dev CA + certyfikat serwera (server, localhost)
docker compose -p webscan --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f tests/TestLab/docker-compose.yml up -d --build
```

| Usługa | Adres |
|---|---|
| Panel administracyjny | http://localhost:8088 (login: `ADMIN_USERNAME` / `ADMIN_PASSWORD` z `.env`) |
| API serwera | https://localhost:5443 (agenci, TLS z dev CA), http://localhost:5080 (wewnętrzne/proxy) |
| RabbitMQ | http://localhost:15672 |
| TestLab | sieć `webscan-lab` 172.30.0.0/24: nginx .10, apache .11, ASP.NET .12 (8080/8443), panel admina .13, baner TCP .14:2323, profil `change` .15:8081 |

Agenci `agent-1` (172.30.0.100) i `agent-2` (172.30.0.101) zapisują się tokenem `AGENT_ENROLLMENT_TOKEN`
(strefa `lab`), polityka zakresu jest zasiana na `172.30.0.0/24`. W panelu: **Networks → New** (`172.30.0.0/24`, strefa `lab`),
**Scans → Start** (workflow `standard-discovery`). Wprowadzenie zmiany do porównania:
`docker compose -p webscan --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f tests/TestLab/docker-compose.yml --profile change up -d change`.

Obserwowalność (opcjonalnie): ustaw `OTLP_ENDPOINT=http://otel-collector:4317` w `.env` i dodaj `--profile observability`
→ Grafana http://localhost:3000 (źródła: Prometheus + PostgreSQL tylko do odczytu), Prometheus http://localhost:9090.

## 2. Tryb deweloperski (bez kontenerów aplikacji)

```bash
docker compose -p webscan --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up -d postgres rabbitmq
dotnet run --project src/Server/Api            # http://localhost:5080, https://localhost:5443, Scalar: /scalar
cd src/Frontend && npm ci && npm run dev       # http://localhost:5173 (proxy /api, /hubs → 5080)
```

Konto deweloperskie: `src/Server/Api/appsettings.Development.json` (`Bootstrap:*`). Frontend bez backendu: `npm run dev:mock`.
Agent lokalnie (tylko syntetyczne narzędzie, bez ruchu sieciowego):

```bash
dotnet run --project src/Agent/Worker -- --Agent:ServerUrl=http://localhost:5080 --Agent:EnrollmentToken=<token z panelu> --Agent:EnableFakeTools=true
```

Token zapisu: **Agents → Enrollment tokens** (opcjonalnie ze strefami). Nowe narzędzia zatwierdza administrator (**Agents → Tools**).

## 3. Testy

```bash
DOCKER_API_VERSION=1.41 dotnet test WebScan.slnx     # jednostkowe + integracyjne (Testcontainers PostgreSQL) + E2E in-process
cd src/Frontend && npm test && npm run typecheck && npm run lint
cd tests/E2ETests/playwright && npx playwright install chromium && npm run test:mocked
```

`DOCKER_API_VERSION` jest potrzebne tylko dla starszego silnika Docker (np. 20.10); fixture'y testów próbują wykryć go same.

**E2E in-process** (`tests/E2ETests/WebScan.E2ETests`): pełny serwer (wszystkie moduły, prawdziwy PostgreSQL, Wolverine)
+ prawdziwi agenci w procesie z syntetycznym narzędziem `fake` (zero ruchu sieciowego). Scenariusze akceptacyjne:

| # | Scenariusz | Test |
|---|---|---|
| 1–8 | migracje, 2 agentów, zakres, podział na rozłączne partie, routing do właściwych agentów, wykonanie, normalizacja, postęp na żywo (SignalR) | `DistributedScanFlowTests` |
| 9 | kolejny skan wykrywa wprowadzoną zmianę | `ChangeDetectionTests` |
| 10 | utrata agenta: brak utraty pracy i duplikatów | `AgentLossTests` |
| 11 | przekroczenie okna przerywa skan, zachowuje dane częściowe | `ScanWindowTests` |
| 12 | RBAC | `RbacTests` |
| 13 | import/eksport JSON/CSV | `ImportExportTests` |
| 14 (+6, 9 z prawdziwymi narzędziami) | własna sygnatura Nuclei wykrywa przygotowaną usługę; prawdziwa zmiana w TestLab | `StackScenarioTests` (wymaga stosu z p. 1) |

Planowanie > 10 000 adresów: `WebScan.Scheduling.UnitTests` (/16 + 20 symulowanych agentów; 16 128 adresów przez kolejkę w PostgreSQL).

**Stack E2E** (prawdziwe nmap/naabu/httpx/nuclei w kontenerach agentów przeciw TestLab):

```bash
set -a; . deploy/docker/.env; set +a
WEBSCAN_STACK_URL=http://localhost:8088 WEBSCAN_STACK_ADMIN_USER=$ADMIN_USERNAME WEBSCAN_STACK_ADMIN_PASSWORD=$ADMIN_PASSWORD \
  dotnet test tests/E2ETests/WebScan.E2ETests --filter FullyQualifiedName~StackScenarioTests
cd tests/E2ETests/playwright && BASE_URL=http://localhost:8088 E2E_ADMIN_USER=$ADMIN_USERNAME E2E_ADMIN_PASSWORD=$ADMIN_PASSWORD npx playwright test --project=stack
```

## 4. Najważniejsza konfiguracja

| Klucz | Znaczenie |
|---|---|
| `ConnectionStrings:WebScan` | PostgreSQL (wszystkie moduły, schemat na moduł) |
| `RabbitMq:ConnectionString` | transport Wolverine; brak = lokalne trwałe kolejki |
| `Auth:Jwt:SigningKey` | klucz JWT (wymagany poza Development) |
| `Bootstrap:AdminUserName/AdminPassword` | pierwszy administrator |
| `Agents:BootstrapEnrollmentToken/BootstrapEnrollmentZones` | token zapisu agentów dla automatyzacji |
| `Agents:HeartbeatTimeoutSeconds` | po jakim czasie agent jest offline (zadania wracają do kolejki) |
| `Networks:SeedScopePolicy:Allowed/Excluded` | początkowa polityka autoryzowanego zakresu |
| `Tools:AutoApprove` | narzędzia zatwierdzane automatycznie (domyślnie nmap, naabu, httpx, nuclei) |
| `Planner:OperationCapabilities`, `Planner:ToolPreference` | mapowanie operacja → capability, preferencje narzędzi |
| `DataProtection:CertificatePath` / `CertificatePassword` | certyfikat PKCS#12 (RSA) chroniący pierścień kluczy, którymi szyfrowane są wrażliwe kolumny (AES-256-GCM, `ARCHITECTURE.md` §6). Brak = klucze w bazie niezaszyfrowane (ostrzeżenie w logu w `Production`); lokalnie klucze generują się same |
| `DataProtection:KeyLifetimeDays` | co ile dni nowy klucz szyfrujący (domyślnie 90); stare klucze zostają do odszyfrowania |
| `OpenTelemetry:OtlpEndpoint` | eksport śladów/metryk/logów |
| `Agent:*` (agent) | `src/Agent/Worker/appsettings.json` — opis każdej opcji w komentarzach |

Limity skanowania (partie, lease, limity na strefę/interfejs/podsieć, globalny rate, docelowy czas zadania `targetJobSeconds`
do adaptacyjnego rozmiaru partii) — `GET/PUT /api/scan-limits` lub panel **Admin**.
