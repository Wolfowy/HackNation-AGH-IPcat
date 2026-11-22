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
      "parser": "naabu-jsonl",         // nmap-xml | naabu-jsonl | httpx-jsonl | nuclei-jsonl | generic-jsonl | <plugin>
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

## Pluginy (kod)

Assembly zbudowane na `src/Agent/Tools.Abstractions` (`IToolAdapter`, `IToolOutputParser`, `IObservationWriter`,
`IToolProcessRunner`) umieszczone w `Agent:PluginPaths`. Ładowane w izolowanym `AssemblyLoadContext`; opcjonalna lista
dozwolonych skrótów `Agent:TrustedPluginSha256`. Pluginy i manifesty instaluje lokalnie operator agenta —
**serwer nigdy ich nie wysyła**.

## Bezpieczeństwo

* Workflow zawiera tylko zatwierdzone typy operacji i zwalidowane parametry — żadnych poleceń ani skryptów.
* Agent waliduje każdy cel względem `ScanJob.AuthorizedScope` i parametry względem schematu, zanim zbuduje argv.
* Nowe narzędzie nie dostaje zadań, dopóki administrator go nie zatwierdzi.
* Szablony Nuclei trafiają do agenta tylko jako zatwierdzone wersje (`SignatureBundle` z weryfikowanym SHA-256).
