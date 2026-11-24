# Project Time Machine 0.7.7

[English](README.md) · [Русский](README_RU.md) · [Українська](README_UK.md)

Lokalna historia projektów, sprawdzane kopie zapasowe i przywracanie z potwierdzeniem
w przeglądarce. FastAPI, Jinja2 i SQLite. Linux z Pythonem 3.11–3.13; interfejs en/ru/pl/uk.
Dołączono konfigurację Docker. Na Windows dostępna jest instalacja przez WSL2, bez natywnego EXE.

## Instalacja

W pobranym katalogu źródeł uruchom jako zwykły użytkownik:

```sh
./install.sh
```

Domyślny katalog to `$HOME/ProjectTimeMachine`. Inny katalog i port:

```sh
./install.sh --prefix "$HOME/MyPTM" --port 13021
"$HOME/MyPTM/bin/setup"
```

Instalator wyświetla adresy interfejsów serwera. Domyślny bind to `0.0.0.0`; w przeglądarce
użyj rzeczywistego IP. Pierwsza konfiguracja administratora przez sieć wymaga kodu z
`"$HOME/ProjectTimeMachine/bin/ptm" setup-code`. Istniejące konto zachowuje hasło.
W niezaufanych sieciach używaj VPN lub HTTPS. [Pełna instrukcja](INSTALL_PL.md).

Dodaj projekt, utwórz Full backup, następnie Incremental/Checkpoint. Porównaj wersje
i sprawdź podgląd przed potwierdzeniem Restore. Najpierw wypróbuj odzyskiwanie na projekcie
testowym. Niestandardowe środowiska wirtualne i generowane pliki runtime wykluczaj jawnie.

## Funkcje i ograniczenia

Wiele projektów i role, migawki metadanych i odzyskiwalne, historia i diff, SHA-256,
weryfikacja łańcucha kopii, harmonogram, SQLite Backup API, opcjonalne AES-GCM,
podgląd przywracania, kopia bezpieczeństwa i dziennik odzyskiwania. Analiza Python AST,
audyt heurystyczny, maskowane raporty oraz przeglądanie logów i SQLite.

Zmiany zwykłych plików mogą zatrzymać backup. Spójność SQLite dotyczy pojedynczej bazy.
Nie gwarantuje się atomowej wymiany całego projektu; przed przywracaniem zatrzymaj zapis.
Migawki samych metadanych nie odtwarzają treści. Maskowanie nie rozpoznaje każdego sekretu.

## Autor i licencja

Author: **Oleksandr**  
Copyright: **© 2026 Oleksandr**  
Kontakt i zgody komercyjne: **omtimemachineom@gmail.com**

**Free for non-commercial use. Commercial use requires prior written permission.**

Bezpłatne użycie niekomercyjne; użycie komercyjne wymaga uprzedniej pisemnej zgody.
[Project Time Machine Non-Commercial License 1.0](LICENSE) to licencja Source-Available
Non-Commercial. Zezwala na osobiste, edukacyjne, badawcze i inne niekomercyjne użycie,
badanie, modyfikowanie i rozpowszechnianie zgodnie z jej warunkami. Komercyjna praca
wewnątrz firmy, sprzedaż, dystrybucja komercyjna i włączenie do komercyjnego produktu
lub płatnej usługi wymagają zgody. Zachowaj autorstwo i wskaż zmiany oraz ich autorów.

Biblioteki zachowują odrębne prawa autorskie i licencje. Oleksandr nie jest ich autorem.
[AUTHORS](AUTHORS) · [COPYRIGHT](COPYRIGHT) · [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
[Współpraca](CONTRIBUTING.md) · [Bezpieczeństwo](SECURITY.md) · [Zmiany](CHANGELOG.md).
