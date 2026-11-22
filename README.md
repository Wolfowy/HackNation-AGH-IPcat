# ip_cat - Distributed Network Discovery & Attack Surface Intelligence

Rozproszona platforma inwentaryzacji i obserwacji infrastruktury sieciowej (10 000+ adresów) w architekturze Controller–Agent.

* **Central Server** (ASP.NET Core .NET 10, modularny monolit): agenci, sieci i polityka zakresu, planer zadań, workflow DAG,
  harmonogramy Quartz, kolejka zadań z dzierżawami, normalizacja i historia obserwacji, wykrywanie zmian, sygnatury,
  RBAC, audyt, eksport/import, DefectDojo, OpenTelemetry.
* **Scanner Agent** (.NET 10 Worker): sam inicjuje połączenia (HTTPS, pull), rejestruje możliwości/interfejsy/trasy,
  uruchamia narzędzia CLI opisane **manifestami** (nmap, naabu, httpx, nuclei, tlsx, … — rozszerzalne bez zmian w kodzie),
  buforuje wyniki w SQLite, obsługuje anulowanie, timeouty, utratę łączności.
* **Panel** (React + TypeScript + Tailwind + shadcn/ui): dashboard, agenci, sieci, skany na żywo (SignalR), harmonogramy,
  workflow, zasoby, zmiany, znaleziska, sygnatury, administracja — widoki zależne od roli.

| Dokument | Zawartość |
|---|---|
| [Publikacja Wiki](docs/WIKI.md) | automatyczna synchronizacja dokumentacji z GitHub Wiki i konfiguracja `WIKI_TOKEN` |
| [Dokumentacja techniczna](docs/DOKUMENTACJA-TECHNICZNA.md) | pełny opis systemu: wdrożenie, działanie skanera, API, import/eksport, RBAC, szyfrowanie i procedura walidacji |
| [docs/RUNNING.md](docs/RUNNING.md) | uruchomienie (Docker Compose, dev), testy, konfiguracja |
| [ARCHITECTURE.md](ARCHITECTURE.md) | architektura, kontrakty, API, bezpieczeństwo, decyzje |
| [docs/LOCAL-NETWORK.md](docs/LOCAL-NETWORK.md) | skanowanie własnej sieci lokalnej (agent natywny) |
| [docs/TOOLS.md](docs/TOOLS.md) | rozszerzalne narzędzia: format manifestu, pluginy, zatwierdzanie |
| [tests/TestLab/README.md](tests/TestLab/README.md) | lokalna sieć testowa (tylko autoryzowane testy) |

Szybki start:

```bash
cp deploy/docker/.env.example deploy/docker/.env && (cd deploy/docker/certs && sh generate-certs.sh)
docker compose -p webscan --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml -f tests/TestLab/docker-compose.yml up -d --build
# panel: http://localhost:8088
```

Skanuj wyłącznie zakresy, do których masz autoryzację. Domyślnie polityka zakresu jest pusta — nic nie zostanie przeskanowane,
dopóki administrator jawnie nie zdefiniuje dozwolonych sieci.
