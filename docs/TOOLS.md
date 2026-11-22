# Rozszerzalne narzędzia skanujące (manifesty)

Agent nie ma zakodowanej listy narzędzi. Każde narzędzie to **manifest JSON** w katalogu `tools.d/`
(`Agent:ToolManifestPaths`), a parser/adapter wybierany jest **po identyfikatorze** z rejestru (wbudowane albo z pluginów).
Serwer wybiera narzędzie **po możliwości** (capability), nigdy po nazwie.

```
manifest (tools.d/*.json) ──► ToolRegistry (sprawdza plik wykonywalny + wersję) ──► AgentRegistration.Tools
                                                                                        │
serwer: katalog narzędzi (zatwierdzanie przez admina) ◄─────────────────────────────────┘
planner: operacja ─► capability (OperationCatalog / Planner:OperationCapabilities) ─► narzędzie agenta (ToolPreference / toolId kroku)
```

## Dodanie nowego narzędzia — bez zmian w kodzie

1. Zainstaluj binarkę na agencie (np. w obrazie `src/Agent/Worker/Dockerfile`).
2. Dodaj manifest `tools.d/<id>.json`. Dla narzędzi emitujących JSONL wystarczy parser `generic-jsonl` z mapowaniem pól
   (przykład: `tlsx.json`). Dla innych formatów — plugin z własnym `IToolOutputParser` (patrz niżej).
3. Restart agenta → agent zgłasza narzędzie w rejestracji → w panelu **Agents → Tools** administrator je zatwierdza
   (nowe identyfikatory są domyślnie niezatwierdzone; `Tools:AutoApprove` na serwerze może je wstępnie zatwierdzić).
4. Workflow używa go automatycznie przez capability albo jawnie przez `toolId` w kroku.

Weryfikacja lokalna: `dotnet WebScan.Agent.Worker.dll --list-tools` (rejestr) i `--run-job job.json` (jedno zadanie bez serwera).

## Format manifestu

```jsonc
{
  "id": "naabu",                       // unikalny identyfikator (= toolId na serwerze)
  "displayName": "naabu",
  "executable": "naabu",               // nazwa z PATH lub ścieżka bezwzględna; alternatywy: "executableCandidates"
  "versionArgs": ["-version"],
  "versionRegex": "[Vv]ersion:?\\s*v?(?<version>\\d+\\.\\d+\\.\\d+)",   // grupa nazwana "version"
  "maxConcurrency": 2,                 // równoległe uruchomienia na agencie
  "defaultTimeoutSeconds": 3600,
  "environment": { },                  // wyłącznie stałe wartości
  "capabilities": {
    "port-scan": {                     // capability (otwarty zbiór; znane: host-discovery, port-scan, service-detection,
                                       //  http-probe, tls-probe, signature-scan, dns-resolve)
      "adapter": "manifest",           // domyślny: generyczny runner szablonu argv; albo id adaptera z pluginu
      "parser": "naabu-jsonl",         // nmap-xml | naabu-jsonl | httpx-jsonl | nuclei-jsonl | nerva-jsonl | generic-jsonl | <plugin>
      "parserOptions": { },            // np. mapowanie pól dla generic-jsonl
      "input":  { "mode": "file", "format": "hosts" },   // file|stdin; hosts|endpoints|urls
      "output": { "mode": "file" },                      // file|stdout
      "arguments": ["-list", "{input}", "-json", "-o", "{output}", "-rate", "{rate}", "-c", "{parallelism}", "-silent"],
      "parameterArguments": {          // mapowanie parametrów operacji (OperationCatalog) na argv
        "ports": { "top-*": ["-top-ports", "{value}"], "*": ["-port", "{value}"] },
        "scanType": { "connect": ["-scan-type", "c"], "syn": ["-scan-type", "s"] },
        "retries": ["-retries", "{value}"]
      },
      "interfaceArguments": ["-interface", "{interface}"]
    }
  }
}
```

Dozwolone placeholdery: `{input} {output} {rate} {timeout} {parallelism} {interface} {templatesDir} {value} {ports} {threadDelayMs}`
oraz `{param:NAZWA}` — każdy inny powoduje odrzucenie manifestu przy ładowaniu. Każdy element szablonu to dokładnie jeden argument
procesu (brak powłoki, `ProcessStartInfo.ArgumentList`); `{value}` i `{param:…}` zaczynające się od `-` są odrzucane; wartości
pochodzą wyłącznie z parametrów zwalidowanych przez `ParameterValidator` (nieznane parametry zadania są odrzucane już na serwerze).

* `{threadDelayMs}` — opóźnienie na wątek (ms), przy którym `{parallelism}` wątków robi ok. `{rate}` połączeń/s; dla narzędzi bez
  globalnego limitu (tlsx: `"-delay", "{threadDelayMs}ms"`). Liczy się jako obsługa parametru `rate`.
* `{param:NAZWA}` — tylko w `parameterArguments`: wartość innego parametru operacji, np. nmap używa `probePorts` wyłącznie
  w metodach TCP: `"method": { "tcp-syn": ["-PS{param:probePorts}"], "icmp": ["-PE"], … }`. Liczy się jako obsługa NAZWY.

**Obsługiwane parametry.** Agent zgłasza `supportedParameters` każdego narzędzia (klucze `parameterArguments`, `{param:…}`,
`rate` przy `{rate}`/`{threadDelayMs}`; adaptery z pluginów — wszystkie parametry swoich operacji). Planer daje zadanie tylko
narzędziu, które obsługuje **każdy parametr ustawiony jawnie w kroku** (wartości domyślne nie są wymaganiem) — narzędzie nie
pominie więc po cichu np. limitu `rate`. Techniki wymagające surowych gniazd (`scanType=syn`, `method=icmp|tcp-ack|arp`) trafiają
tylko do agentów z `rawSockets` ≠ false (`Agent:RawSockets`, domyślnie wykrywane: root, `CAP_NET_RAW` albo `NMAP_PRIVILEGED`).

### `generic-jsonl` — narzędzie bez kodu

`parserOptions`: `kind` (rodzaj obserwacji), `fields` (pole obserwacji → ścieżka JSON z kropkami), `attributes`
(dodatkowe pary klucz/ścieżka), `requireFields`, `discriminator` (część identyfikatora obserwacji). Pełny przykład: `tools.d/tlsx.json`.

### `httpx` — fingerprinting HTTP

Stałe argumenty `tools.d/httpx.json`: `-json -status-code -title -web-server -content-type -content-length -ip -hash sha256
-include-response-header -tls-grab -kb -cdn=true` (+ `-follow-redirects`, `-max-redirects`, `-tech-detect`, `-favicon`, `-path`
z parametrów `HttpProbe`). `-kb` (klasyfikacja strony) i `-cdn` (CDN/WAF z zakresów IP) działają lokalnie na tej samej odpowiedzi —
bez dodatkowych żądań. `-include-chain` celowo pominięte (surowe odpowiedzi). Parser `httpx-jsonl` mapuje:

| pole httpx (v1.12) | `HttpDetails` |
|---|---|
| `header` (snake_case → nazwy z myślnikami) | `Headers` (wartości ciasteczek i tokeny maskowane) |
| `header.set_cookie` (powtórzenia złączone `", "`) | `Cookies[]`: nazwa, Secure, HttpOnly, SameSite, Domain, Path — **nigdy wartość**; F5 `BIGipServer*` → zdekodowany wewnętrzny `IP:port` (`DecodedValue`); `CookieNames` zostaje dla zgodności |
| `location`, `final_url`, `chain_status_codes` | `RedirectChain` (URL → Location → final), `FinalUrl`, `RedirectStatusCodes` |
| `favicon`, `favicon_md5` | `FaviconHash` (mmh3), `FaviconMd5` |
| `knowledgebase.PageType` | `PageType` (np. `login`, `error`, `parked`) |
| `cdn_name`, `cdn_type` | `Cdn`, `CdnType` (`cdn` / `waf` / `cloud`) |
| `tls.subject_dn` | `TlsDetails.SubjectDn` |

Starsze agenty (tylko zamaskowany nagłówek `Set-Cookie`): serwer odtwarza `Cookies` z nazw i atrybutów nagłówka.

### Rapid7 recog — identyfikacja produktów i urządzeń (serwer)

Moduł Discovery dopasowuje już zebrane dane do odcisków [Rapid7 recog](https://github.com/rapid7/recog)
(BSD-2-Clause, © Rapid7; licencja: `src/Server/Modules/Discovery/Fingerprinting/Recog/LICENSE`), bez żadnego ruchu do celów:
nagłówek `Server` → `http_servers.xml`, tytuł → `html_title.xml`, nazwy ciasteczek → `http_cookies.xml`, `WWW-Authenticate` →
`http_wwwauth.xml`, MD5 favikony → `favicons.xml`, banery SSH/FTP → `ssh_banners.xml` / `ftp_banners.xml`, DN certyfikatu →
`x509_subjects.xml` / `x509_issuers.xml`. Wersja przypięta: **recog v3.3.3**. Aktualizacja: pobrać te same pliki z
`https://raw.githubusercontent.com/rapid7/recog/<tag>/xml/<plik>.xml` do katalogu `Fingerprinting/Recog/`, zmienić wersję tutaj
i uruchomić `RecogTests` (każdy `<example>` musi pasować do swojego odcisku i dać zadeklarowane parametry).

### Cele wejściowe narzędzi: hosty wirtualne

`TargetFormatter` adresuje endpoint **nazwą** (`ScanEndpoint.Hostname`), gdy jest znana — URL `https://app.example.com:443`,
SNI i nagłówek Host trafiają do właściwego vhosta — a w przeciwnym razie adresem IP. Linie są deduplikowane, grupowanie
`{ports}` (nmap) idzie po nazwie. Ponieważ narzędzie samo rozwiązuje nazwę, **nazwa musi należeć do zakresu**: planer
zostawia `Hostname` tylko, gdy nazwa jest w sieci (wtedy adres może leżeć poza nią — cele domenowe), inaczej ją usuwa i
sprawdza adres; agent odrzuca endpoint, którego `Hostname ?? Address` jest poza `AuthorizedScope`. Łańcuch
discover → ports → services → http zachowuje nazwę: kroki hostowe dostają nazwę i adres (planer bierze to, co w zakresie,
a rozwiązany adres celu domenowego nie liczy się jako „poza zakresem”), kroki endpointowe dostają osobny endpoint na każdy
vhost, a goły adres obok nazwanego endpointu jest pomijany (bez podwójnego sondowania; jego `scheme` jest zachowany).

### Porty z polityki zakresu

`ScanJob.AuthorizedPorts` (np. `80,443,8000-8079,8081-8100`; brak = wszystkie) pochodzi z `AllowedPorts − ExcludedPorts`
polityki. Planer przycina `ports` i `probePorts` (tylko metody pingu TCP) oraz endpointy; `top-N` zamienia na jawną listę
**nmap top-N ∩ dozwolone** (wbudowana lista 1000 najczęstszych portów TCP z nmap-services 7.95), dla N > 1000 — na samą
listę dozwolonych (a przy samych wykluczeniach odrzuca krok). Agent odrzuca zadanie z endpointem lub parametrem portów poza
`AuthorizedPorts` (także `top-N`, którego nie da się sprawdzić). Manifesty nie muszą nic robić: dostają jawną listę.

### masscan — szybki przegląd dużych zakresów

`tools.d/masscan.json` ([robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan), AGPL-3.0, pakiet Debiana
w obrazie agenta, `cap_net_raw` na binarce): `port-scan` asynchronicznym SYN-skanem, wyjście `-oX` czytane parserem `nmap-xml`
(masscan nie zapisuje `<status>` — otwarty port dowodzi, że host żyje). Wbudowane workflow zaczynają od kroku `sweep`
(`toolId: masscan`, porty top-1000 + typowe porty usług, `rate` 10000 — dalej ograniczane przez `Agent:MaxRatePerSecond`, domyślnie
2000, oraz limity globalne); dokładne skanowanie nmap/naabu idzie już tylko na hosty z wynikami przeglądu.

* `requiresRawSockets: true` — agent z `rawSockets: false` dostaje zamiast masscana inne narzędzie `port-scan`.
* `acceptsHostnames: false` — masscan nie rozwiązuje nazw; paczki z nazwami domen idą do naabu/nmap.
* `interfaceArguments: ["-e", "{interface}", "--router-ip", "{gateway}"]` — masscan wysyła ramki na MAC routera; `{gateway}` to
  brama trasy na interfejsie zadania, a bez niej pierwszy adres podsieci interfejsu (sieci Dockera, typowe LAN-y). Bez tego masscan
  na interfejsie bez trasy domyślnej czeka w nieskończoność na router.

### nerva — alternatywne rozpoznawanie usług

`tools.d/nerva.json` ([praetorian-inc/nerva](https://github.com/praetorian-inc/nerva), Apache-2.0, utrzymywany fork
fingerprintx): `service-detection` dla znanych otwartych `host:port` (170+ wtyczek protokołów: RDP, LDAP, SMB, ICS, bazy,
fingerprinty produktów HTTP). Wyjście `--json` (`host, ip, port, protocol, tls, transport, version, metadata`) mapuje parser
`nerva-jsonl` na obserwacje `Service` (nazwa, wersja, `tls` → tunnel `ssl`, CPE, baner, skalarne metadane jako zamaskowane
atrybuty `nerva.*`; nagłówki odpowiedzi pomijane) oraz `Technology` z `metadata.technologies`. `--deep` i `--misconfigs`
są **wyłączone** (dodają sondy ścieżek admina, logowania i błędnych konfiguracji). Obsługuje tylko parametr `rate`.

Wybór: planer domyślnie bierze nmap (`Planner:ToolPreference:service-detection` = `["nmap"]`, ustawienie klucza zastępuje
domyślne); krok workflow wybiera nervę przez `"toolId": "nerva"` (krok z jawnym `versionIntensity`/`grabBanner` zostaje przy
nmap). Nowe id nie jest zatwierdzone automatycznie — admin zatwierdza je w **Agents → Tools**. Obraz agenta zawiera
binarkę (wersja i SHA-256 przypięte w Dockerfile); lokalnie `go install github.com/praetorian-inc/nerva/cmd/nerva@latest`.
nerva nie ma flagi wersji, więc agent zgłasza wersję `unknown`; brak binarki = narzędzie po prostu niezgłoszone.

## Pluginy (kod)

Assembly zbudowane na `src/Agent/Tools.Abstractions` (`IToolAdapter`, `IToolOutputParser`, `IObservationWriter`,
`IToolProcessRunner`) umieszczone w `Agent:PluginPaths`. Ładowane w izolowanym `AssemblyLoadContext`; opcjonalna lista
dozwolonych skrótów `Agent:TrustedPluginSha256`. Pluginy i manifesty instaluje lokalnie operator agenta —
**serwer nigdy ich nie wysyła**.

## Bezpieczeństwo

* Workflow zawiera tylko zatwierdzone typy operacji i zwalidowane parametry — żadnych poleceń ani skryptów.
* Agent waliduje każdy cel względem `ScanJob.AuthorizedScope`, porty względem `ScanJob.AuthorizedPorts` i parametry względem schematu, zanim zbuduje argv.
* Nowe narzędzie nie dostaje zadań, dopóki administrator go nie zatwierdzi.
* Szablony Nuclei trafiają do agenta tylko jako zatwierdzone wersje (`SignatureBundle` z weryfikowanym SHA-256).
