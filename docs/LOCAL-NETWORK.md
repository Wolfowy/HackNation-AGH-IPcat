# Skanowanie własnej sieci lokalnej

> Skanuj wyłącznie sieci, do których masz uprawnienia (własna sieć domowa / zgoda właściciela sieci).
> W sieci firmowej skanowanie bez zgody działu IT/bezpieczeństwa może naruszać politykę i prawo.

Serwer i panel działają w Docker Compose, a **agent uruchamiany jest natywnie na komputerze w skanowanej sieci**.
Na macOS i Windows Docker Desktop trzyma kontenery w osobnej maszynie wirtualnej (NAT), więc agent w kontenerze nie widzi
sieci lokalnej jak zwykły host (brak ARP/ICMP, zafałszowane wyniki). Na Linuksie można alternatywnie użyć kontenera agenta
z `network_mode: host`.

## 1. Serwer i panel

```bash
cp deploy/docker/.env.example deploy/docker/.env            # ustaw sekrety (hasło admina, token agentów, ...)
(cd deploy/docker/certs && sh generate-certs.sh)
docker compose -p webscan --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml up -d --build
```

Panel: http://localhost:8088 (login z `ADMIN_USERNAME` / `ADMIN_PASSWORD`). API dla agentów: https://localhost:5443.
TestLab i kontenerowi agenci nie są potrzebni (agenci z Compose mają tylko strefę `lab`, więc i tak nie dostaną zadań z sieci lokalnej).

## 2. Ustal adres sieci

macOS:

```bash
route -n get default | grep interface          # np. en0
ipconfig getifaddr en0                         # np. 192.168.1.23
ipconfig getoption en0 subnet_mask             # np. 255.255.255.0  → sieć 192.168.1.0/24
```

Linux: `ip -4 route show default` i `ip -4 addr show <interfejs>`.

## 3. Autoryzacja zakresu w panelu (Administrator)

1. **Networks → Scope policy**: dodaj sieć (np. `192.168.1.0/24`) do *Allowed*. Bez tego żadna sieć z tego zakresu nie da się utworzyć ani przeskanować.
2. **Networks → Zones**: dodaj strefę, np. `home`.
3. **Networks → New network**: nazwa `home-lan`, strefa `home`, zakres `192.168.1.0/24`; w *Exclusions* wpisz adresy,
   których nie chcesz dotykać (np. drukarki, urządzenia medyczne, IoT).
4. **Agents → Enrollment tokens → New**: strefy `home`, auto-approve, 1 użycie → skopiuj token (pokazywany raz).

## 4. Agent natywnie na komputerze w tej sieci

```bash
brew install nmap naabu httpx nuclei          # macOS; Linux: pakiet nmap + binarki ProjectDiscovery z GitHub Releases
go install github.com/praetorian-inc/nerva/cmd/nerva@latest   # opcjonalnie: nerva (README nie podaje formuły brew; albo binarka z GitHub Releases)
dotnet run --project src/Agent/Worker -c Release -- --list-tools     # sprawdzenie wykrytych narzędzi (bez skanowania)

dotnet run --project src/Agent/Worker -c Release -- \
  --Agent:ServerUrl=https://localhost:5443 \
  --Server:CaCertificatePath="$PWD/deploy/docker/certs/ca.crt" \
  --Agent:AgentId=home-agent \
  --Agent:EnrollmentToken=<TOKEN_Z_PANELU> \
  --Agent:DataDirectory="$HOME/.webscan-agent" \
  --Agent:MaxRatePerSecond=300
```

Token jest potrzebny tylko przy pierwszym starcie (poświadczenia zapisują się w `DataDirectory`, plik z prawami 600).
W panelu **Agents** agent `home-agent` powinien być *Active / online* ze strefą `home` i narzędziami nmap/naabu/httpx/nuclei.
Jeśli dodałeś inne narzędzia (np. tlsx, nerva), zatwierdź je w **Agents → Tools catalog**. Brak binarki nerva niczego nie psuje:
agent po prostu jej nie zgłasza.

Planer wybiera interfejs, którego podsieć obejmuje skanowany zakres (np. `en0`), więc ruch idzie bezpośrednio do sieci lokalnej.

### Sieci z podsieci agentów (skan „wszerz”)

Zamiast wpisywać sieci ręcznie: **Networks → Agent subnets** pokazuje podsieci, w których siedzą podłączone agenty
(i te, do których mają trasę przez bramę). Zaznaczone są domyślnie podsieci bezpośrednie, mieszczące się w polityce zakresu,
jeszcze niepokryte siecią i niebędące łączem agenta z serwerem (*server link*, np. sieć Dockera). **Create networks** tworzy
sieci z tagiem `agent-subnet`; potem skan na tych sieciach jak zwykle. Podsieć spoza polityki (*outside / partly inside*)
Administrator może dodać przyciskiem **Add to scope policy** (z potwierdzeniem) — tylko jeśli ma autoryzację do skanowania tej sieci.
Planer daje każdą podsieć agentom podłączonym do niej bezpośrednio; agent, który sięga tylko przez bramę domyślną, dostaje ją
dopiero, gdy żaden bezpośredni nie jest online.

## 5. Skan

**Scans → Start scan**: workflow `standard-discovery`, sieć `home-lan`, opcjonalnie okno czasowe (minuty) i limit pakietów/s.
Postęp widać na żywo; wyniki w **Assets** (hosty, usługi, technologie, certyfikaty), **Findings** (sygnatury),
a po kolejnych skanach w **Changes**. Cykliczne skanowanie: **Schedules** (cron w składni Quartz, np. `0 0 2 * * ?` = 02:00).

`standard-discovery`: wykrywanie hostów (TCP ping na 22/80/443/3389/8080) → top-1000 portów TCP → wykrywanie usług →
HTTP/TLS → zatwierdzone sygnatury (domyślnie tylko `info`/`low`) → zapis → porównanie z poprzednim skanem.

## Wskazówki

* **Uprawnienia nmap**: bez roota nmap używa pingów TCP connect — hosty z zaporą odrzucającą wszystko po cichu (np. telefony)
  mogą zostać pominięte. Opcje: utwórz wersję workflow z `DiscoverHosts.method = none` (każdy adres traktowany jako aktywny;
  wolniej, ale kompletnie) albo uruchom agenta z uprawnieniami do surowych pakietów (ICMP/ARP) — świadomie, bo wtedy cały agent
  działa jako root. Agent bez uprawnień zgłasza to serwerowi (`rawSockets: false`), więc kroki z `scanType=syn` albo
  `method=icmp|tcp-ack|arp` nie trafią do niego (zadanie czeka na agenta z uprawnieniami, np. kontener) zamiast kończyć się błędem nmap.
* **Łagodność**: `Agent:MaxRatePerSecond` i limit skanu w formularzu ograniczają ruch; domowe routery źle znoszą bardzo szybkie skany.
* **Własne sygnatury**: **Signatures → New** (szablon Nuclei YAML, walidacja odrzuca szablony inwazyjne), zatwierdzenie przez administratora.
* **Kilka perspektyw**: uruchom kolejnych agentów w innych segmentach sieci (każdy z własnym tokenem/strefą).
