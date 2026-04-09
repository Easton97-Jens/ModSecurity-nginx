# 1. Kurzfassung

Dieses Repository ist der **ModSecurity-nginx-Connector**: ein nginx-Modul, das nginx mit **libmodsecurity (ModSecurity v3)** verbindet. Es enthält nicht die eigentliche WAF-Regelengine, sondern vor allem Brückenlogik (Daten aus nginx lesen, an libmodsecurity übergeben, Interventionsentscheidung in nginx umsetzen). Die Kernlogik ist in C implementiert (`src/*.c`), ergänzt durch Header (`src/*.h`) und nginx-Buildintegration (`config`). Das Modul registriert sich in Access- und Log-Phase sowie als Header-/Body-Filter. Es definiert Konfigurationsdirektiven wie `modsecurity`, `modsecurity_rules*`, `modsecurity_transaction_id` und `modsecurity_use_error_log`. Tests liegen als nginx-Testfälle in Perl vor (`tests/*.t`).

---

# 2. Einfache Erklärung für Einsteiger

Du hast drei Bausteine:

1. **nginx** nimmt HTTP-Anfragen an und liefert Antworten.
2. **libmodsecurity** ist die WAF-Engine (Regeln auswerten, Blocken/Redirect entscheiden).
3. **dieses Repo** verbindet beide.

Der Connector liest Request-/Response-Daten aus nginx (Methode, URI, Header, Body) und ruft damit libmodsecurity auf. Danach fragt er: „Gibt es eine Intervention?“ Wenn ja, setzt er z. B. einen Statuscode oder Redirect in nginx. Wenn nein, läuft alles normal weiter.

Wichtig: Die eigentliche Sicherheitslogik (Regeln, Matching, Transformationen) ist in libmodsecurity, nicht in diesem Repo.

---

# 3. Technische Tiefenanalyse

## 3.1 Zweck des Repos

**Beleg:** `README.md`, Einleitung.
- Das README bezeichnet das Projekt explizit als Verbindungspunkt zwischen nginx und libmodsecurity.
- Es sagt auch klar: dieses Projekt hängt von **libmodsecurity** ab, nicht von ModSecurity 2.x.

## 3.2 Sprache und Repo-Struktur

**Beleg:** Dateibaum + Quelltexte.
- Kernlogik: C (`src/ngx_http_modsecurity_*.c`)
- Header/Strukturen: C-Header (`src/ngx_http_modsecurity_common.h`, `src/ddebug.h`)
- Buildintegration: nginx-addon-Skript `config`
- Tests: Perl (`tests/*.t`, `Test::Nginx`)
- Zusatz: Windows-Builddoku (`win32/README.md`)

## 3.3 Zentrale Dateien

- `src/ngx_http_modsecurity_module.c`: Moduldefinition, Direktiven, Konfigurationen, Hook-Registrierung, Intervention-Handling.
- `src/ngx_http_modsecurity_access.c`: Request-Verarbeitung inkl. Connection/URI/Header/Body an libmodsecurity.
- `src/ngx_http_modsecurity_header_filter.c`: Response-Header an libmodsecurity.
- `src/ngx_http_modsecurity_body_filter.c`: Response-Body an libmodsecurity.
- `src/ngx_http_modsecurity_log.c`: Logging-Brücke und Log-Phase-Handler.
- `src/ngx_http_modsecurity_common.h`: zentrale Kontext- und Config-Strukturen.

## 3.4 nginx-Moduldefinition und Integration

**Beleg:** `src/ngx_http_modsecurity_module.c`.
- Direktiven stehen in `ngx_http_modsecurity_commands[]`.
- nginx-Modulobjekt ist `ngx_http_modsecurity_module`.
- In `ngx_http_modsecurity_init()` wird registriert:
  - Access-Handler: `ngx_http_modsecurity_access_handler`
  - Log-Handler: `ngx_http_modsecurity_log_handler`
  - Header-Filter-Init: `ngx_http_modsecurity_header_filter_init()`
  - Body-Filter-Init: `ngx_http_modsecurity_body_filter_init()`

## 3.5 Verbindung zu libmodsecurity

**Beleg:** `src/ngx_http_modsecurity_module.c`, `src/ngx_http_modsecurity_access.c`, `src/ngx_http_modsecurity_header_filter.c`, `src/ngx_http_modsecurity_body_filter.c`, `src/ngx_http_modsecurity_log.c`.

Sichtbare API-Aufrufe:
- Initialisierung: `msc_init()`, `msc_set_connector_info()`, `msc_set_log_cb()`
- Transaktion: `msc_new_transaction()` / `msc_new_transaction_with_id()`
- Request:
  - `msc_process_connection()`
  - `msc_process_uri()`
  - `msc_add_n_request_header()`
  - `msc_process_request_headers()`
  - `msc_append_request_body()` / `msc_request_body_from_file()`
  - `msc_process_request_body()`
- Response:
  - `msc_add_n_response_header()`
  - `msc_process_response_headers()`
  - `msc_append_response_body()`
  - `msc_process_response_body()`
- Entscheidung/Logging:
  - `msc_intervention()`
  - `msc_update_status_code()`
  - `msc_process_logging()`

## 3.6 Request-Verarbeitung

**Beleg:** `ngx_http_modsecurity_access_handler()` in `src/ngx_http_modsecurity_access.c`.

Ablauf (sichtbar im Code):
1. Location-Config lesen und prüfen, ob `modsecurity` aktiv ist.
2. Kontext/Transaktion anlegen, falls noch nicht vorhanden.
3. Verbindungsdaten (Client/Server Addr/Port) an libmodsecurity übergeben.
4. URI/Methode/HTTP-Version übergeben.
5. Request-Header iterieren und übergeben.
6. Request-Header verarbeiten lassen (`msc_process_request_headers`).
7. Request-Body lesen (asynchron), aus Datei oder Speicherkette an libmodsecurity übergeben.
8. Request-Body final verarbeiten (`msc_process_request_body`).
9. Nach mehreren Schritten jeweils Intervention prüfen.

## 3.7 Response-/Interventionsverarbeitung

### Response-Header
**Beleg:** `ngx_http_modsecurity_header_filter()` in `src/ngx_http_modsecurity_header_filter.c`.
- Standard-/dynamische Response-Header werden gesammelt und an libmodsecurity übergeben.
- Danach: `msc_process_response_headers()` und Intervention prüfen.

### Response-Body
**Beleg:** `ngx_http_modsecurity_body_filter()` in `src/ngx_http_modsecurity_body_filter.c`.
- Response-Body-Chunks werden übergeben (`msc_append_response_body`).
- Am Ende: `msc_process_response_body()` und Intervention prüfen.

### Interventionen
**Beleg:** `ngx_http_modsecurity_process_intervention()` in `src/ngx_http_modsecurity_module.c`.
- Fragt mit `msc_intervention()` die Entscheidung ab.
- Falls `intervention.url` gesetzt ist: baut `Location`-Header und gibt Status zurück.
- Falls nur Status ≠ 200: aktualisiert Status im ModSecurity-Transaktionsobjekt und gibt Status zurück.
- Optional frühes Logging (`early_log`) möglich.

## 3.8 Logging

**Beleg:** `src/ngx_http_modsecurity_log.c`, `src/ngx_http_modsecurity_module.c`.
- `ngx_http_modsecurity_log()` schreibt Meldungen via `ngx_log_error(..., NGX_LOG_INFO, ...)`.
- Dieser Callback wird mit `msc_set_log_cb()` registriert.
- In der nginx-Log-Phase ruft das Modul `msc_process_logging()` auf.
- Zusätzlich kann Interventions-Log in nginx-Error-Log geschrieben werden; abschaltbar über `modsecurity_use_error_log`.

## 3.9 Konfigurationsdirektiven

**Beleg:** `ngx_http_modsecurity_commands[]` + README.

Direktiven:
- `modsecurity on|off`
- `modsecurity_rules <rule>`
- `modsecurity_rules_file <path>`
- `modsecurity_rules_remote <key> <url>`
- `modsecurity_transaction_id <string/complex value>`
- `modsecurity_use_error_log on|off`

Konfigurationsverarbeitung:
- pro Location: `ngx_http_modsecurity_create_conf()`
- Merge parent/child: `ngx_http_modsecurity_merge_conf()`
- Regelmengen werden mit `msc_rules_merge()` zusammengeführt.

## 3.10 Build und Einbindung

**Beleg:** `config`, `README.md`, `win32/README.md`.
- `config` prüft, ob `libmodsecurity` vorhanden ist (Featuretest über `msc_init`).
- Modulquellen werden als nginx-addon registriert.
- README zeigt Einbindung per `--add-module` (statisch) oder `--add-dynamic-module --with-compat` (dynamisch).
- `config` enthält Modulreihenfolge-Logik für Filter.
- Windows-Doku beschreibt Buildpfad und nennt dort statische Einbindung als praktischen Weg in diesem Setup.

## 3.11 Grenzen des Repos

- **Nicht im Repo enthalten:** interne Rule-Engine von libmodsecurity.
- **Nicht vollständig im Repo belegbar:** konkrete Security-Wirkung bestimmter Regelsets; genaue Performance-Aussagen.
- **nginx-Kernverhalten** (volle Phasen-/Filter-Interna) liegt außerhalb dieses Repos.

---

# 4. Datei-für-Datei-Überblick

## `README.md`
- **Rolle:** Projektzweck, Direktiven, Build-Usage.
- **Warum wichtig:** offizielle Abgrenzung Connector vs. libmodsecurity.
- **Lernwert:** Wie Nutzer das Modul bauen und konfigurieren.

## `config`
- **Rolle:** nginx-Build-Integration.
- **Warum wichtig:** zeigt Abhängigkeiten und Modulreihenfolge.
- **Lernwert:** Woher `-lmodsecurity` kommt und wie Quellen eingebunden werden.

## `src/ngx_http_modsecurity_module.c`
- **Rolle:** Modulregistrierung, Direktiven, Main-/Loc-Config, Interventionen.
- **Warum wichtig:** zentrale Integrationsdatei.
- **Lernwert:** Wie nginx-API und libmodsecurity-API verbunden werden.

## `src/ngx_http_modsecurity_access.c`
- **Rolle:** Request-Pipeline.
- **Warum wichtig:** zeigt, wann welche Request-Daten übergeben werden.
- **Lernwert:** praktische Reihenfolge: Connection → URI → Header → Body → Intervention.

## `src/ngx_http_modsecurity_header_filter.c`
- **Rolle:** Response-Header-Pipeline.
- **Warum wichtig:** Übergabe von Headern und Status an libmodsecurity.
- **Lernwert:** Response-Hook vor Body-Verarbeitung.

## `src/ngx_http_modsecurity_body_filter.c`
- **Rolle:** Response-Body-Pipeline.
- **Warum wichtig:** Chunk-basierte Übergabe und Interventionsprüfung.
- **Lernwert:** wie Streaming-Daten in die Engine gehen.

## `src/ngx_http_modsecurity_log.c`
- **Rolle:** Logging-Brücke.
- **Warum wichtig:** verbindet libmodsecurity-Logs mit nginx-Logsystem.
- **Lernwert:** wann Logging in der nginx-Log-Phase erfolgt.

## `src/ngx_http_modsecurity_common.h`
- **Rolle:** gemeinsame Strukturen und Prototypen.
- **Warum wichtig:** zeigt Kontextflags und Konfigurationszustand.
- **Lernwert:** internes Zustandsmodell des Connectors.

## `tests/*.t` (z. B. `modsecurity.t`, `modsecurity-config.t`, `modsecurity-transaction-id.t`)
- **Rolle:** Verhaltenstests im nginx-Testframework.
- **Warum wichtig:** zeigt erwartetes Laufzeitverhalten (Block/Redirect/Merge/TX-ID).
- **Lernwert:** welche Integrationsfälle real abgesichert sind.

---

# 5. Request-Lebenszyklus

1. nginx empfängt Anfrage.
2. Access-Handler des Connectors läuft (wenn `modsecurity on`).
3. Connector erzeugt ModSecurity-Transaction-Kontext.
4. Connector übergibt Verbindungsdaten (Client/Server).
5. Connector übergibt URI, Methode, HTTP-Version.
6. Connector übergibt Request-Header.
7. Connector lässt Request-Header von libmodsecurity verarbeiten.
8. Connector liest Request-Body (asynchron), übergibt Datei oder Buffer-Chunks.
9. Connector lässt Request-Body verarbeiten.
10. Nach den Schritten prüft Connector immer wieder `msc_intervention`.
11. Bei Antwort: Header-Filter übergibt Response-Header + Status, prüft Intervention.
12. Body-Filter übergibt Response-Body-Chunks, verarbeitet final, prüft Intervention.
13. In Log-Phase wird Logging über libmodsecurity abgeschlossen.

---

# 6. Klare Abgrenzung der Verantwortlichkeiten

## nginx
- HTTP-Serverbetrieb, Eventloop, Netzwerk-I/O.
- Request-/Response-Lebenszyklus und Phasensteuerung.
- Filterkette und endgültige Antwortauslieferung.

## ModSecurity-nginx-Connector (dieses Repo)
- nginx-Hooks registrieren.
- Daten aus nginx extrahieren und an libmodsecurity weiterreichen.
- Interventionen in nginx-Status/Redirect umsetzen.
- Connector-Konfigurationsdirektiven verwalten.

## libmodsecurity
- Regel-Engine (Parsing, Evaluation, Actions, Anomalie-/Entscheidungslogik).
- Erzeugung der Interventionen.
- ModSecurity-seitige Audit-/Debug-Mechanik.

**Wenn Detail intern nicht sichtbar:** im Repository nicht eindeutig belegbar.

---

# 7. Belegübersicht

1. **Repo ist Connector, nicht Engine**  
   - Datei: `README.md`  
   - Kontext: Einleitungsabsatz  
   - Beleg: "connection point" zwischen nginx und libmodsecurity.

2. **Modul-Hooks in Access/Log/Header/Body**  
   - Datei: `src/ngx_http_modsecurity_module.c`  
   - Funktion: `ngx_http_modsecurity_init`  
   - Beleg: Handler-/Filter-Registrierung sichtbar.

3. **Direktivenliste**  
   - Datei: `src/ngx_http_modsecurity_module.c`  
   - Struktur: `ngx_http_modsecurity_commands[]`  
   - Beleg: `modsecurity*`, `transaction_id`, `use_error_log`.

4. **Request-Datenübergabe**  
   - Datei: `src/ngx_http_modsecurity_access.c`  
   - Funktion: `ngx_http_modsecurity_access_handler`  
   - Beleg: `msc_process_connection`, `msc_process_uri`, Header-/Body-Aufrufe.

5. **Response-Datenübergabe**  
   - Dateien: `src/ngx_http_modsecurity_header_filter.c`, `src/ngx_http_modsecurity_body_filter.c`  
   - Funktionen: `ngx_http_modsecurity_header_filter`, `ngx_http_modsecurity_body_filter`  
   - Beleg: `msc_process_response_headers`, `msc_process_response_body`.

6. **Intervention-Umsetzung**  
   - Datei: `src/ngx_http_modsecurity_module.c`  
   - Funktion: `ngx_http_modsecurity_process_intervention`  
   - Beleg: Redirect/Statuscode/Logging-Pfade.

7. **Buildabhängigkeit libmodsecurity**  
   - Datei: `config`  
   - Kontext: Featuretest und Fehlerfall  
   - Beleg: `-lmodsecurity`, Abbruch bei fehlender Lib.

8. **Tests existieren und decken Integrationsfälle ab**  
   - Dateien: `tests/modsecurity.t`, `tests/modsecurity-config.t`, `tests/modsecurity-transaction-id.t`  
   - Kontext: Perl-Testfälle  
   - Beleg: Redirect/Block/Merge/Transaction-ID-Prüfungen.

---

# 8. Unsicherheiten / nicht eindeutig belegbare Punkte

- Interne Engine-Details von libmodsecurity (Regelparser, Matching-Interna) sind **nicht im Connector-Repo enthalten**.
- Konkrete Security-Wirkung eines beliebigen Regelsets ist **aus diesem Repo allein nicht sicher ableitbar**.
- Allgemeingültige Performance-Aussagen sind **nicht eindeutig belegbar**.
- Vollständige nginx-Kern-Details (außerhalb der aufgerufenen APIs) sind **nicht Teil dieses Repos**.

---

# 9. TL;DR für Backend-Entwickler

- C-basiertes nginx-Modul als Connector zu libmodsecurity.
- Nicht die eigentliche WAF-Engine.
- Registriert Access-/Log-Handler plus Header-/Body-Filter.
- Übergibt Request und Response schrittweise an libmodsecurity.
- Prüft nach Verarbeitungspunkten auf Interventionen.
- Setzt Interventionsresultate als nginx-Status/Redirect um.
- Konfigurierbar über `modsecurity*`, `modsecurity_transaction_id`, `modsecurity_use_error_log`.
- Buildintegration via `config`, harte Abhängigkeit auf libmodsecurity.
- Tests zeigen Integrationsverhalten (Block, Redirect, Merge, TX-ID).
- Grenzen: Engine-Interna liegen in libmodsecurity, nicht hier.

---

# 10. Wie ich dieses Repo einem Junior-Entwickler in 2 Minuten erklären würde

Das hier ist ein Adaptermodul für nginx. Es macht aus nginx keinen eigenen WAF-Kern, sondern verbindet nginx mit libmodsecurity. Der Connector hängt sich in mehrere nginx-Stellen ein: beim Request-Zugriff, beim Response-Header, beim Response-Body und beim Logging. Er nimmt die Daten, die nginx ohnehin hat (z. B. URI, Header, Body), und ruft damit die libmodsecurity-Funktionen auf. Danach fragt er, ob libmodsecurity eingreifen will. Wenn ja, setzt er den von der Engine gelieferten Effekt in nginx um (z. B. HTTP-Status oder Redirect). Wenn nein, geht der Request normal weiter. Für neue Entwickler ist wichtig: Dieses Repo erklärt das Integrationsverhalten sehr gut, aber nicht die innere Regel-Engine. Für echte Regel-/Securitylogik musst du parallel in libmodsecurity schauen.

---

# 11. Welche 5 Dateien ich als Erstes lesen würde und warum

1. **`src/ngx_http_modsecurity_module.c`**  
   Zentrale Einstiegspunkte: Direktiven, Modulregistrierung, Konfig-Merge, Intervention.

2. **`src/ngx_http_modsecurity_access.c`**  
   Klarster Request-Datenfluss Richtung libmodsecurity.

3. **`src/ngx_http_modsecurity_header_filter.c`**  
   Zeigt Response-Header-Integration und Statusverarbeitung.

4. **`src/ngx_http_modsecurity_body_filter.c`**  
   Zeigt Response-Body-Übergabe in Chunk-Form.

5. **`config`**  
   Zeigt Build-/Link-Integration in nginx inkl. Abhängigkeiten und Modulreihenfolge.
