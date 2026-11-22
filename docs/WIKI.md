# Publikacja dokumentacji w GitHub Wiki

Pliki `docs/**/*.md` są źródłem stron GitHub Wiki. Workflow `.github/workflows/publish-wiki.yml` publikuje je po zmianach na `main`; można go też uruchomić ręcznie przez **Actions → Publish documentation to Wiki → Run workflow** dla gałęzi `main`.

## Jednorazowa konfiguracja repozytorium

1. W **Settings → General → Features** włączyć **Wikis**.
2. Otworzyć zakładkę **Wiki**, utworzyć pierwszą stronę `Home` i zapisać ją. Dopiero po pierwszym zapisie GitHub udostępnia repozytorium `REPOSITORY.wiki.git` do klonowania.
3. Utworzyć personal access token konta mającego prawo zapisu do tego repozytorium. Dla tokenu classic wybrać `public_repo` w repozytorium publicznym lub `repo` w prywatnym. Nadać datę wygaśnięcia i odnawiać sekret przed jej upływem.
4. Dodać token jako sekret repozytorium **Settings → Secrets and variables → Actions → New repository secret**, pod nazwą `WIKI_TOKEN`.
5. Wysłać workflow na `main` i uruchomić go ręcznie lub zmienić plik w `docs`.

Publikacja korzysta z osobnego tokenu do repozytorium Wiki. Workflow nadaje zwykłemu `GITHUB_TOKEN` wyłącznie prawo odczytu kodu. Sekret nie jest zapisywany w URL repozytorium ani konfiguracji Git; uwierzytelnianie odbywa się przez tymczasowy `GIT_ASKPASS`.

Instrukcja GitHub: [lokalna edycja i pierwsze utworzenie Wiki](https://docs.github.com/en/communities/documenting-your-project-with-wikis/adding-or-editing-wiki-pages), [zarządzanie tokenami](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).

## Zasady synchronizacji

- Każdy plik Markdown staje się osobną stroną. `docs/RUNNING.md` tworzy stronę `RUNNING`, a `docs/subdir/Guide.md` stronę `subdir--Guide`.
- `Home`, `_Sidebar` i `_Footer` powstają automatycznie. Nazwy te są zarezerwowane i nie mogą występować jako strony źródłowe.
- Linki do innych dokumentów w `docs` wskazują odpowiadające im strony Wiki. Linki do plików poza `docs` prowadzą do rewizji kodu, z której wykonano publikację. Obrazy wskazują surowe pliki repozytorium. Fragmenty kodu zachowują oryginalną treść.
- Usunięcie lub zmiana nazwy dokumentu usuwa poprzednią wygenerowaną stronę na podstawie manifestu `.webscan-wiki-pages.json` w repozytorium Wiki.
- Strony dodane ręcznie, których generator wcześniej nie publikował, pozostają zachowane. Edycje ręczne stron generowanych, w tym `Home`, zostaną zastąpione przy następnej synchronizacji. Zmiany dokumentacji należy wprowadzać w `docs` przez Git lub edytor GitHub.
- Publikacja tworzy commit tylko wtedy, gdy treść Wiki się zmieniła. Workflow nie używa force push. Równoległe publikacje są kolejkowane.
- Generator waliduje lokalne linki i odrzuca kolizje nazw stron. Obsługuje standardowe linki Markdown i definicje odnośników; surowy HTML oraz składnia linków `[[...]]` nie są przekształcane.

## Sprawdzenie lokalne

Wymagany jest Node.js 22 lub nowszy. Generator nie wymaga instalacji paczek npm ani tokenu:

```bash
node --test scripts/tests/build-wiki.test.mjs
node scripts/build-wiki.mjs --source docs --output .wiki-preview --repository Wolfowy/HackNation-AGH-IPcat --ref main
```

Podgląd tworzy pliki Markdown w `.wiki-preview`. Nie publikuje ich na GitHub. Błędy dotyczące brakującego sekretu, pierwszej strony Wiki lub uprawnień są raportowane w kroku **Publish Wiki** w GitHub Actions.
