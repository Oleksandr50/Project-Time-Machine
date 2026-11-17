# Project Time Machine 0.7.6 — Linux

## Instalacja

Wymagania: Linux 5.3+, Python 3.11–3.13 z venv, tar/gzip i internet do pobrania
zależności. Ubuntu: `sudo apt install python3-venv`. Instalator uruchamiaj jako zwykły
użytkownik, bez sudo. Istniejący Python z uv jest wykrywany automatycznie.

```sh
sha256sum -c SHA256SUMS
tar -xzf project-time-machine-0.7.6-linux.tar.gz
cd project-time-machine-0.7.6
./install.sh
```

Archiwum można rozpakować w dowolnym miejscu. Domyślna instalacja:
`$HOME/ProjectTimeMachine`; dane są oddzielone od kodu releases. Własny katalog i port:

```sh
./install.sh --prefix "$HOME/MyPTM" --port 13021
```

Domyślny port to 13011; jeśli jest zajęty, wybierany jest wolny. Jawnie podany zajęty
port powoduje błąd, bez zatrzymywania innych procesów. `--no-start` pomija start,
a `--wheelhouse /absolute/wheels` pozwala użyć lokalnych pakietów. Instalator nie wymaga
root, nie zmienia zapory ani obcych usług. Wbudowana samokontrola używa danych tymczasowych.

## Bezpośredni dostęp sieciowy

Domyślny bind **0.0.0.0** obejmuje wszystkie interfejsy IPv4. Instalator wyświetla
rzeczywiste adresy URL. Otwórz `http://ADRES_SERWERA:PORT` przez Ethernet/Wi-Fi/VPN,
także dla adresów 100.64.0.0/10. Tunel SSH i ręczne dodawanie podsieci nie są potrzebne.
0.0.0.0 jest adresem nasłuchiwania, nie adresem przeglądarki. Dla IPv6 wybierz bind `::`.
HTTP nie szyfruje połączenia; w niezaufanej sieci używaj HTTPS. Nieznane Host oraz
niezaufane nagłówki proxy nie są automatycznie akceptowane. Jawne ograniczenia IP/Host
właściciela pozostają. Routing i zapora systemu nie są zmieniane.

## Administrator

Jeśli administrator już istnieje, otwórz `/login` i użyj dotychczasowego loginu/hasła.
Ponowna konfiguracja ani kod aktywacyjny nie są wtedy potrzebne.
Przy nowej instalacji otwórz `/setup` bezpośrednio przez sieć. Na serwerze wykonaj:

```sh
"$HOME/ProjectTimeMachine/bin/ptm" setup-code
```

Dla innej instalacji użyj jej `bin/ptm`. Wpisz jednorazowy kod właściciela, wybierz język,
login i hasło (minimum 12 znaków), a następnie potwierdź hasło. Kod jest usuwany po
utworzeniu administratora; nie trafia do URL ani logu serwera. Nie ma domyślnej pary
admin/admin. Konfiguracja lokalna również działa.

## Codzienna praca

1. Projects → Add: nazwa i bezwzględna ścieżka katalogu na serwerze. HOME pozwala dodawać
   projekty wewnętrzne bez dodatkowych komend. Kod/dane/klucze/archiwa PTM są chronione.
2. Wybierz projekt, wykonaj Full Backup i poczekaj na sukces.
3. Po zmianach wykonuj Incremental lub Checkpoint; Compare pokazuje różnice snapshotów.
   Snapshot Metadata Only nie gwarantuje możliwości odtworzenia zawartości.
4. Restore: wybierz backup/odtwarzalny snapshot, cały projekt/pliki/nowy katalog,
   sprawdź podgląd i potwierdź RESTORE. Przed nadpisaniem powstaje zweryfikowana kopia
   zabezpieczająca. Zatrzymaj procesy zapisujące projekt. Pierwszą próbę wykonaj na
   małym, tymczasowym projekcie.
5. Backups: harmonogram dzienny/tygodniowy. Automatyczne usuwanie jest domyślnie wyłączone.
6. Analysis/Audit nie poprawiają automatycznie źródeł. Logs/SQLite pokazują ograniczone
   wyniki z maskowaniem rozpoznanych sekretów; SQLite nie służy do edycji danych.
7. Users: Viewer/Operator, tylko wybrane projekty i osobne uprawnienie Restore.
   Settings: język ru/en/pl/uk, motyw i skala.

W Projekty → Edytuj → Wykluczenia dodaj ścieżki względne do środowisk wirtualnych o własnych
nazwach, np. `data/voice/tts_venv`. Standardowe `venv` i `.venv` są już wykluczone; inne nazwy
nie są wykluczane automatycznie. Dowiązania symboliczne i pliki specjalne zatrzymują kopię
z czytelnym błędem, zamiast powodować kopiowanie poza katalogiem projektu.

## Ustawienia i sterowanie

```sh
"$HOME/ProjectTimeMachine/bin/setup"
"$HOME/ProjectTimeMachine/bin/ptm" status
"$HOME/ProjectTimeMachine/bin/ptm" start
"$HOME/ProjectTimeMachine/bin/ptm" stop
"$HOME/ProjectTimeMachine/bin/ptm" restart
```

Działają również `./setup.sh` oraz `./setup.sh --prefix "$HOME/MyPTM"` z archiwum.
Menu zmienia katalogi projektów/nowych backupów, bind, port i autostart. Save zapisuje
zmiany. Pusty Enter zachowuje IP/port. Stare archiwa nie są przenoszone ani kasowane.
Usługa startowa to wyłącznie własna systemd user-unit po jawnym wyborze; linger może
wymagać zgody systemu. Inne usługi nie są zmieniane.

Jawne wyłączenie sieci przez administratora pozostaje po aktualizacji. Właściciel może
przywrócić dostęp z terminala bez tunelu i bez resetowania kont:

```sh
"$HOME/ProjectTimeMachine/bin/ptm" network-on
# Wyłączenie: bin/ptm network-off
```

Dodatkowe katalogi przyjmują ścieżki bezwzględne i ~/. Katalogi systemowe, dane
uwierzytelniania i ścieżki symlink są chronione.

## Aktualizacja i usuwanie

Rozpakuj nowy pakiet osobno:

```sh
./install.sh --prefix "$HOME/ProjectTimeMachine"
```

Konta, ID, historia, archiwa, ustawienia oraz bind/port pozostają. Jeżeli wcześniej
wybrano 127.0.0.1, ustaw 0.0.0.0 w setup. Błędny app_root starszych wersji nie wymaga
ręcznej edycji ani linków. Przed migracją powstaje checkpoint SQLite. Przerwana
aktualizacja: `bin/ptm recover-update`; przerwany Save: `bin/setup --recover`, potem jawny
start. Nie ma automatycznego obniżania wersji DB po zakończonej aktualizacji.

```sh
"$HOME/ProjectTimeMachine/bin/ptm" uninstall
```

Polecenie wyłącza własną kopię i launchery. Bazy, projekty, backupy, klucze i kod powrotu
pozostają. Nie kasuj katalogu danych, jeśli chcesz zachować historię.

Autor: Oleksandr. © 2026 Oleksandr. Kontakt: omtimemachineom@gmail.com.
Obowiązuje Project Time Machine Non-Commercial License 1.0 w pliku LICENSE.
Bezpłatne użycie osobiste, edukacyjne i niekomercyjne, badanie, modyfikowanie oraz
niekomercyjne rozpowszechnianie są dozwolone z zachowaniem autorstwa i wskazaniem zmian.
Użycie i rozpowszechnianie komercyjne wymagają uprzedniej pisemnej zgody.
Odrębne licencje bibliotek zachowano w THIRD_PARTY_NOTICES.md i third_party/.
