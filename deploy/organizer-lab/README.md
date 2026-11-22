# WebScan na szablonie laboratorium organizatora

Osobna instancja WebScan (własna baza, kolejka i agenci, panel na porcie **9088**) do testów na szablonach
środowisk od organizatora HackNation („Attack Surface Intelligence”). Nie koliduje z głównym stosem (`deploy/docker`, port 8088).

## Uruchomienie

1. Obrazy `webscan-server`, `webscan-frontend`, `webscan-agent` muszą być zbudowane (`docker compose ... build` z `deploy/docker`).
2. Uruchom jeden stack organizatora, np. `custom-network` (katalog z plikami organizatora):

   ```bash
   docker compose -f docker-compose-custom-network.yml up -d
   ```

3. Sprawdź jego sieci i podsieci (agenci dołączą do nich jak do skanowanej sieci):

   ```bash
   docker network inspect hacknation-custom-network_frontend hacknation-custom-network_backend -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}}{{end}}'
   ```

4. Skonfiguruj i uruchom instancję:

   ```bash
   cp deploy/organizer-lab/.env.example deploy/organizer-lab/.env   # sekrety: openssl rand -hex 24; LAB_NET_A/B, LAB_SCOPE
   docker compose -p webscan-orglab --env-file deploy/organizer-lab/.env -f deploy/organizer-lab/docker-compose.yml up -d
   ```

   Polityka zakresu startuje z `LAB_SCOPE` (tylko podsieci laboratorium). Agenci `lab-agent-1/2` rejestrują się sami w strefie `lab`.

5. Panel: <http://localhost:9088>, login `admin`, hasło `ADMIN_PASSWORD` z `deploy/organizer-lab/.env`.
   W **Networks** dodaj sieci w strefie `lab` (np. `172.25.0.0/24`, `172.24.0.0/24` — Docker przydziela adresy od początku
   podsieci; całe `/16` też zadziała, ale samo wykrywanie hostów trwa wtedy ok. 40 min), potem **Scans → Start scan**
   z workflow `standard-discovery` (masscan na cały zakres, potem top-1000 na znalezionych hostach) albo `full-discovery`
   (po przeglądzie masscanem wszystkie porty 1-65535 na znalezionych hostach). Agenci laboratorium mają podniesiony limit
   `Agent:MaxRatePerSecond` (`LAB_AGENT_RATE`, domyślnie 20000), żeby przegląd masscanem był szybki.

## Scenariusz z README organizatora (znikająca i powracająca usługa)

| Krok | Akcja | Oczekiwany efekt w WebScan |
|---|---|---|
| 1 | skan 1 (wszystko działa) | hosty i usługi: nginx :80 (8787), Gitea :3000/:22, RabbitMQ :5672/:15672, PostgreSQL :5432, httpbin :80 |
| 2 | `docker compose -f docker-compose-custom-network.yml stop flask-app`, skan 2 | usługi nginx znikają z przebiegu (porównanie skanów, ponowny pomiar `RecheckMissing`), reszta bez zmian |
| 3 | `docker compose -f docker-compose-custom-network.yml up -d flask-app`, skan 3 | nginx wraca (zmiana „reappeared”/nowe usługi) |

Wyniki: **Dashboard**, **Scans → przebieg → porównanie z innym przebiegiem**, **Changes**, **Inventory → Services** (szczegóły HTTP).

## Sprzątanie

```bash
docker compose -p webscan-orglab --env-file deploy/organizer-lab/.env -f deploy/organizer-lab/docker-compose.yml down -v
docker compose -f docker-compose-custom-network.yml down
```
