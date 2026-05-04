# 1. Kurzfassung
Dieses Repository ist ein nginx-Connector-Modul für ModSecurity v3 (libmodsecurity) und nicht die WAF-Engine selbst. Die README beschreibt es ausdrücklich als Verbindungspunkt zwischen nginx und libmodsecurity. Der Connector liest Daten aus nginx-Request/Response-Strukturen und ruft damit libmodsecurity-Funktionen auf. Wenn libmodsecurity eine Intervention meldet, setzt der Connector diese Entscheidung in nginx (Statuscode/Redirect) um. Die Kernlogik ist in C implementiert (`src/*.c`, `src/*.h`), Tests sind überwiegend Perl-Dateien (`tests/*.t`), und die nginx-Build-Einbindung liegt in `config`. Im Code ist kein JSON-Serialisierungsfluss als Austauschmodell sichtbar; stattdessen sind viele einzelne API-Aufrufe mit Strings, Längen und Pointern erkennbar. Header werden paarweise übergeben, Body-Daten chunk-weise oder dateibasiert, und Metadaten (URI/Methode/Version/Status) per separaten Funktionsaufrufen. Diese Aussagen sind direkt im Connector-Code nachvollziehbar. 【F:README.md†L8-L13】【F:src/ngx_http_modsecurity_access.c†L215-L226】【F:src/ngx_http_modsecurity_access.c†L262-L267】【F:src/ngx_http_modsecurity_access.c†L394-L419】【F:src/ngx_http_modsecurity_header_filter.c†L503-L531】【F:config†L90-L161】

# 2. Einfache Erklärung für Einsteiger
Der Connector ist ein Adapter zwischen nginx und libmodsecurity:
- nginx hat die HTTP-Anfrage/-Antwort.
- libmodsecurity trifft Sicherheitsentscheidungen.
- dieses Repo verbindet beides.

Was praktisch passiert:
1. Das Modul hängt sich in nginx-Phasen/Filter ein.
2. Es nimmt Felder aus nginx (z. B. URI, Methode, Header, Body).
3. Es ruft dazu passende libmodsecurity-APIs auf.
4. Es fragt, ob eine Intervention vorliegt (z. B. blocken/redirect).
5. Falls ja, setzt es das Ergebnis in nginx um.

Wichtig zur Formatfrage: Im sichtbaren Connector-Code wird **kein JSON gebaut oder geparst**. Stattdessen werden Daten **feldweise per API** übergeben (z. B. URI separat, Header als Key/Value-Paare, Body als Bytes/Chunks oder aus Datei). Ein einheitliches Austauschformat (eine einzige serialisierte Nachricht) ist im Repo nicht sichtbar. 【F:src/ngx_http_modsecurity_module.c†L567-L624】【F:src/ngx_http_modsecurity_access.c†L215-L226】【F:src/ngx_http_modsecurity_access.c†L262-L267】【F:src/ngx_http_modsecurity_access.c†L406-L419】【F:src/ngx_http_modsecurity_module.c†L159-L162】【F:src/ngx_http_modsecurity_module.c†L182-L221】

# 3. Technische Tiefenanalyse
## 3.1 Zweck des Repos
- README: „connection point“ zwischen nginx und libmodsecurity; Modul ist nötig, um LibModSecurity mit nginx zu verwenden. 【F:README.md†L8-L13】
- Das Repo ist Connector-/Integrationslogik, nicht komplette WAF-Engine. 【F:README.md†L8-L13】【F:src/ngx_http_modsecurity_common.h†L25-L27】

## 3.2 Sprache und Repo-Struktur
- Kernlogik: C (`src/ngx_http_modsecurity_*.c`). 【F:config†L119-L124】
- Header: C (`src/ngx_http_modsecurity_common.h`). 【F:src/ngx_http_modsecurity_common.h†L17-L27】
- Buildintegration: `config` (nginx-addon-Skript). 【F:config†L1-L2】【F:config†L90-L161】
- Tests: Perl + Test::Nginx (`tests/*.t`). 【F:tests/modsecurity.t†L22-L31】
- Windows-Buildhinweise separat in `win32/README.md`. 【F:win32/README.md†L1-L10】

## 3.3 Zentrale Dateien
- `src/ngx_http_modsecurity_module.c`: Moduldefinition, Direktiven, Hook-Registrierung, Config-Erzeugung/-Merge, Intervention-Umsetzung. 【F:src/ngx_http_modsecurity_module.c†L483-L564】【F:src/ngx_http_modsecurity_module.c†L567-L624】【F:src/ngx_http_modsecurity_module.c†L697-L788】【F:src/ngx_http_modsecurity_module.c†L140-L247】
- `src/ngx_http_modsecurity_access.c`: Request-Lesepfad und Übergabe an libmodsecurity. 【F:src/ngx_http_modsecurity_access.c†L46-L57】【F:src/ngx_http_modsecurity_access.c†L162-L166】【F:src/ngx_http_modsecurity_access.c†L215-L226】
- `src/ngx_http_modsecurity_header_filter.c`: Response-Header-Verarbeitung. 【F:src/ngx_http_modsecurity_header_filter.c†L411-L537】
- `src/ngx_http_modsecurity_body_filter.c`: Response-Body-Verarbeitung. 【F:src/ngx_http_modsecurity_body_filter.c†L38-L39】【F:src/ngx_http_modsecurity_body_filter.c†L149-L175】
- `src/ngx_http_modsecurity_log.c`: Log-Callback und Log-Phase. 【F:src/ngx_http_modsecurity_log.c†L27-L36】【F:src/ngx_http_modsecurity_log.c†L39-L74】
- `src/ngx_http_modsecurity_common.h`: zentrale Strukturen (`ctx`, `main_conf`, `loc_conf`). 【F:src/ngx_http_modsecurity_common.h†L80-L127】

## 3.4 nginx-Moduldefinition und Integration
- Direktiven sind in `ngx_http_modsecurity_commands[]` registriert. 【F:src/ngx_http_modsecurity_module.c†L483-L533】
- Modulobjekt: `ngx_http_modsecurity_module` vom Typ `NGX_HTTP_MODULE`. 【F:src/ngx_http_modsecurity_module.c†L551-L564】
- Hook-Registrierung in `ngx_http_modsecurity_init()`:
  - Access-Phase-Handler,
  - Log-Phase-Handler,
  - Header-Filter,
  - Body-Filter. 【F:src/ngx_http_modsecurity_module.c†L588-L621】
- Konfig pro Kontext:
  - main: create/init,
  - location: create/merge,
  - server create/merge ist hier `NULL`. 【F:src/ngx_http_modsecurity_module.c†L536-L548】

## 3.5 Verbindung zu libmodsecurity
- Initialisierung: `msc_init()`, Connector-Info, Log-Callback. 【F:src/ngx_http_modsecurity_module.c†L662-L672】
- Transaktion pro Request: `msc_new_transaction*`. 【F:src/ngx_http_modsecurity_module.c†L291-L299】
- Request-Übergaben: `msc_process_connection`, `msc_process_uri`, `msc_add_n_request_header`, `msc_process_request_headers`, `msc_append_request_body`, `msc_request_body_from_file`, `msc_process_request_body`. 【F:src/ngx_http_modsecurity_access.c†L162-L166】【F:src/ngx_http_modsecurity_access.c†L225-L226】【F:src/ngx_http_modsecurity_access.c†L262-L276】【F:src/ngx_http_modsecurity_access.c†L406-L419】【F:src/ngx_http_modsecurity_access.c†L447-L449】
- Response-Übergaben: `msc_add_n_response_header`, `msc_process_response_headers`, `msc_append_response_body`, `msc_process_response_body`. 【F:src/ngx_http_modsecurity_header_filter.c†L503-L531】【F:src/ngx_http_modsecurity_body_filter.c†L149-L164】
- Intervention/Logging: `msc_intervention`, `msc_update_status_code`, `msc_process_logging`. 【F:src/ngx_http_modsecurity_module.c†L159-L162】【F:src/ngx_http_modsecurity_module.c†L231-L236】【F:src/ngx_http_modsecurity_log.c†L69-L72】

## 3.6 Datenmodell und Datenübergabe
### Grundmodell
- Sichtbar ist ein **API-basiertes Feldmodell** (viele einzelne Funktionsaufrufe).
- Sichtbar sind C-Zeiger, Bytepointer, Längenangaben, nginx-`ngx_str_t`/Listen/Ketten.
- Es gibt im Connector keinen sichtbar implementierten „einheitlichen Nachrichtencontainer“ (z. B. ein JSON-Objekt mit allen Feldern). 【F:src/ngx_http_modsecurity_common.h†L80-L127】【F:src/ngx_http_modsecurity_access.c†L262-L267】【F:src/ngx_http_modsecurity_body_filter.c†L149-L150】

### JSON-Prüfung
- Suche im Connector-Code zeigt keine JSON-Bau-/Parse-Logik; Treffer zu `yajl` stehen im Build-Skript als Link-Option, nicht als Datenpfad im Connector-Code. 【F:config†L8-L23】
- Daher: **Im Connector-Code kein JSON-Datenübergabepfad eindeutig belegt**.

### Datenform im Detail (Kurz)
- `ngx_str_t` wird teils in nullterminierte C-Strings kopiert (`ngx_str_to_char`) für API-Aufrufe. 【F:src/ngx_http_modsecurity_module.c†L114-L136】
- Header werden als Name/Wert + Länge pro Header übergeben (`msc_add_n_request_header`, `msc_add_n_response_header`). 【F:src/ngx_http_modsecurity_access.c†L262-L267】【F:src/ngx_http_modsecurity_header_filter.c†L503-L507】
- Body wird als Bytes aus Buffer-Ketten übergeben oder per Dateipfad. 【F:src/ngx_http_modsecurity_access.c†L394-L419】【F:src/ngx_http_modsecurity_access.c†L406-L407】
- URI/Methode/Version werden separat in `msc_process_uri` übergeben. 【F:src/ngx_http_modsecurity_access.c†L215-L226】
- Status/Redirect kommen aus `ModSecurityIntervention`-Struct zurück. 【F:src/ngx_http_modsecurity_module.c†L143-L147】【F:src/ngx_http_modsecurity_module.c†L182-L221】

## 3.7 Request-Verarbeitung
- Access-Handler prüft `modsecurity on`. 【F:src/ngx_http_modsecurity_access.c†L53-L57】
- Kontext erzeugen, Transaction initialisieren. 【F:src/ngx_http_modsecurity_access.c†L85-L92】【F:src/ngx_http_modsecurity_module.c†L279-L299】
- Connectiondaten übergeben. 【F:src/ngx_http_modsecurity_access.c†L162-L166】
- URI/Methode/Version übergeben. 【F:src/ngx_http_modsecurity_access.c†L215-L226】
- Request-Header iterieren und paarweise übergeben. 【F:src/ngx_http_modsecurity_access.c†L239-L267】
- Header verarbeiten + Intervention prüfen. 【F:src/ngx_http_modsecurity_access.c†L274-L285】
- Body asynchron lesen; bei `NGX_AGAIN` warten. 【F:src/ngx_http_modsecurity_access.c†L355-L371】
- Body aus Datei oder Bufferketten übergeben, final verarbeiten, Intervention prüfen. 【F:src/ngx_http_modsecurity_access.c†L394-L458】

## 3.8 Response-/Interventionsverarbeitung
- Header-Filter sammelt/überträgt Header, verarbeitet Response-Header in libmodsecurity, prüft Intervention. 【F:src/ngx_http_modsecurity_header_filter.c†L472-L537】
- Body-Filter überträgt Body-Bytes je Chain-Element, verarbeitet finalen Response-Body, prüft Intervention. 【F:src/ngx_http_modsecurity_body_filter.c†L143-L175】
- Intervention-Funktion reagiert auf `status`, `url`, `log`, setzt ggf. `Location`-Header und liefert nginx-Status zurück. 【F:src/ngx_http_modsecurity_module.c†L143-L147】【F:src/ngx_http_modsecurity_module.c†L182-L221】【F:src/ngx_http_modsecurity_module.c†L223-L246】

## 3.9 Logging
- libmodsecurity-Logcallback schreibt in nginx-Logging (`ngx_log_error`, INFO). 【F:src/ngx_http_modsecurity_log.c†L27-L36】
- Registrierung des Callbacks bei Init. 【F:src/ngx_http_modsecurity_module.c†L671-L672】
- Log-Phase ruft `msc_process_logging`. 【F:src/ngx_http_modsecurity_log.c†L69-L72】
- Interventionslogs optional ins nginx-Error-Log, steuerbar über Direktive. 【F:src/ngx_http_modsecurity_module.c†L169-L176】【F:src/ngx_http_modsecurity_module.c†L525-L530】

## 3.10 Konfigurationsdirektiven
- Registrierte Direktiven: `modsecurity`, `modsecurity_rules`, `modsecurity_rules_file`, `modsecurity_rules_remote`, `modsecurity_transaction_id`, `modsecurity_use_error_log`. 【F:src/ngx_http_modsecurity_module.c†L483-L533】
- Regeln laden via `msc_rules_add*`; Merge via `msc_rules_merge`. 【F:src/ngx_http_modsecurity_module.c†L364-L410】【F:src/ngx_http_modsecurity_module.c†L437-L449】【F:src/ngx_http_modsecurity_module.c†L777-L787】

## 3.11 Build und Einbindung
- README zeigt `--add-module` und `--add-dynamic-module`. 【F:README.md†L29-L37】
- `config` prüft libmodsecurity-Feature und bricht bei Fehlen ab. 【F:config†L11-L17】【F:config†L82-L87】
- `config` listet Modulquellen/-deps und Filter-Order-Logik. 【F:config†L119-L137】【F:config†L164-L197】

## 3.12 Grenzen des Repos
- Interne Rule-Evaluation-Logik ist nicht im Connector, sondern in libmodsecurity. 【F:README.md†L8-L13】【F:src/ngx_http_modsecurity_common.h†L25-L27】
- Vollständige nginx-Kerninterna (außer aufgerufene APIs) sind außerhalb dieses Repos.
- Aussage zu Performance/Sicherheitswirkung konkreter Regeln: aus dem vorliegenden Connector-Code nicht sicher ableitbar.

# 4. Datenfluss-Tabelle
| Datenart | Quelle in nginx | Interne Repräsentation im Connector | Weitergabe an libmodsecurity | Sichtbares Format | Beleg |
|---|---|---|---|---|---|
| Methode | `r->method_name` | `ngx_str_t` → ggf. C-String via `ngx_str_to_char` | `msc_process_uri(..., method, ...)` | Feldweise API, String | `src/ngx_http_modsecurity_access.c` `ngx_http_modsecurity_access_handler`【F:src/ngx_http_modsecurity_access.c†L216-L226】 |
| URI | `r->unparsed_uri` | `ngx_str_t` → C-String | `msc_process_uri(uri, method, version)` | Feldweise API, String | gleiche Stelle【F:src/ngx_http_modsecurity_access.c†L215-L226】 |
| Query String | nicht separat sichtbar übergeben; Query evtl. Teil von `unparsed_uri` | keine separate Connector-Struktur sichtbar | kein separater API-Call im Connector sichtbar | aus Code: kein eigenes Austauschobjekt | kein eigener Übergabecall gefunden; nur `unparsed_uri`-Pfad【F:src/ngx_http_modsecurity_access.c†L215-L226】 |
| HTTP-Version | `r->http_version` / `r->http_protocol` | Switch auf C-String (`"1.1"`, etc. oder aus Protokollstring) | `msc_process_uri(..., http_version)` | Feldweise API, String | `src/ngx_http_modsecurity_access.c`【F:src/ngx_http_modsecurity_access.c†L186-L213】【F:src/ngx_http_modsecurity_access.c†L225-L226】 |
| Request-Header | `r->headers_in.headers` (ngx list) | Iteration über `ngx_list_part_t`/`ngx_table_elt_t` | pro Header `msc_add_n_request_header(name,len,val,len)` | Key/Value + Länge je Header | `src/ngx_http_modsecurity_access.c`【F:src/ngx_http_modsecurity_access.c†L239-L267】 |
| Request-Body | `r->request_body->bufs` oder `temp_file` | `ngx_chain_t`-Buffers / Dateipfad (`ngx_str_t`) | `msc_append_request_body(bytes,len)` oder `msc_request_body_from_file(path)` + `msc_process_request_body()` | Byte-Chunk oder Dateipfad, kein JSON | `src/ngx_http_modsecurity_access.c`【F:src/ngx_http_modsecurity_access.c†L394-L419】【F:src/ngx_http_modsecurity_access.c†L406-L407】【F:src/ngx_http_modsecurity_access.c†L447-L449】 |
| Response-Header | `r->headers_out` + `r->headers_out.headers` | Resolver + List-Iteration | pro Header `msc_add_n_response_header(name,len,val,len)` + `msc_process_response_headers(status,version)` | Key/Value + Länge je Header | `src/ngx_http_modsecurity_header_filter.c`【F:src/ngx_http_modsecurity_header_filter.c†L472-L531】 |
| Response-Body | Body-Filter-Chain `ngx_chain_t *in` | `chain->buf->pos/last` Bytes | `msc_append_response_body(bytes,len)` + am Ende `msc_process_response_body()` | Byte-Chunk | `src/ngx_http_modsecurity_body_filter.c`【F:src/ngx_http_modsecurity_body_filter.c†L143-L164】 |
| Client-IP / Connection-Infos | `connection->addr_text`, `sockaddr`, `local_sockaddr` | `ngx_str_t`/Ports → C-String + ints | `msc_process_connection(client_addr,client_port,server_addr,server_port)` | Feldweise API | `src/ngx_http_modsecurity_access.c`【F:src/ngx_http_modsecurity_access.c†L78-L105】【F:src/ngx_http_modsecurity_access.c†L162-L166】 |
| Intervention-Ergebnis | `ModSecurityIntervention intervention` | C-Struct Felder: `status`, `url`, `log`, `disruptive` | `msc_intervention(...)`; Ergebnis wird in nginx-Status/Headers umgesetzt | Struct-basiert, kein JSON | `src/ngx_http_modsecurity_module.c` `ngx_http_modsecurity_process_intervention`【F:src/ngx_http_modsecurity_module.c†L143-L147】【F:src/ngx_http_modsecurity_module.c†L159-L162】【F:src/ngx_http_modsecurity_module.c†L182-L246】 |

# 5. Datei-für-Datei-Überblick
- `README.md`
  - Rolle: Zweck, Direktiven, Build-Hinweise.
  - Warum wichtig: beschreibt offiziell die Connector-Rolle.
  - Man lernt: Abgrenzung zu libmodsecurity + Nutzungsdirektiven.
  - Auffällig: Direktiven-Dokumentation und Build-Optionen. 【F:README.md†L8-L13】【F:README.md†L29-L37】【F:README.md†L47-L187】

- `config`
  - Rolle: nginx-Buildintegration.
  - Warum wichtig: echte Modulaufnahme und Linkabhängigkeiten.
  - Man lernt: Abhängigkeitsprüfung, Quellenliste, Modulorder.
  - Auffällig: `-lmodsecurity`, dynamic/static branches. 【F:config†L11-L17】【F:config†L116-L161】

- `src/ngx_http_modsecurity_module.c`
  - Rolle: Modulgerüst.
  - Warum wichtig: zentrale Integration und Intervention.
  - Man lernt: Hooks, Direktiven, Config-Lifecycle.
  - Auffällig: `ngx_http_modsecurity_process_intervention`, `ngx_http_modsecurity_init`. 【F:src/ngx_http_modsecurity_module.c†L140-L247】【F:src/ngx_http_modsecurity_module.c†L567-L624】

- `src/ngx_http_modsecurity_access.c`
  - Rolle: Request-Pipeline.
  - Warum wichtig: zeigt Datenerfassung/-übergabe am klarsten.
  - Man lernt: Feldweise API-Aufrufe (Connection, URI, Header, Body).
  - Auffällig: Body-Handhabung via Datei/Buffer/Chunks. 【F:src/ngx_http_modsecurity_access.c†L162-L166】【F:src/ngx_http_modsecurity_access.c†L215-L226】【F:src/ngx_http_modsecurity_access.c†L394-L419】

- `src/ngx_http_modsecurity_header_filter.c`
  - Rolle: Response-Header-Hook.
  - Warum wichtig: zeigt Header-Übergabeformat und Statusverarbeitung.
  - Man lernt: pro-Header-Calls + `msc_process_response_headers`.
  - Auffällig: eigene Resolverliste für wichtige Header. 【F:src/ngx_http_modsecurity_header_filter.c†L36-L69】【F:src/ngx_http_modsecurity_header_filter.c†L472-L531】

- `src/ngx_http_modsecurity_body_filter.c`
  - Rolle: Response-Body-Hook.
  - Warum wichtig: chunk-weise Weitergabe sichtbar.
  - Man lernt: stream-artige Übergabe über `ngx_chain_t`.
  - Auffällig: finale Verarbeitung bei `last_buf`. 【F:src/ngx_http_modsecurity_body_filter.c†L143-L164】【F:src/ngx_http_modsecurity_body_filter.c†L157-L160】

- `src/ngx_http_modsecurity_log.c`
  - Rolle: Logging-Brücke.
  - Warum wichtig: zeigt Einsatz von nginx-Logging + ModSecurity-Loggingphase.
  - Man lernt: Log-Callback und `msc_process_logging()`. 【F:src/ngx_http_modsecurity_log.c†L27-L36】【F:src/ngx_http_modsecurity_log.c†L69-L72】

- `src/ngx_http_modsecurity_common.h`
  - Rolle: zentrale Typen und Zustandsflags.
  - Warum wichtig: zeigt, wie Connector intern Zustand hält.
  - Man lernt: `ctx`-Flags (`waiting_more_body`, `processed`, etc.) und conf-Strukturen. 【F:src/ngx_http_modsecurity_common.h†L97-L127】

# 6. Request-Lebenszyklus
1. **Access-Phase-Einstieg**: Modul wird über nginx-Phase aufgerufen. (Form: nginx Request-Struct `ngx_http_request_t *r`). 【F:src/ngx_http_modsecurity_module.c†L588-L595】
2. **Enable-Prüfung**: `mcf->enable` in Location-Config. (Form: ngx conf struct). 【F:src/ngx_http_modsecurity_access.c†L53-L57】
3. **Context/Transaction**: ggf. neue `Transaction*` erzeugen. (Form: C-Struct/Pointer). 【F:src/ngx_http_modsecurity_module.c†L279-L299】
4. **Connectiondaten**: Client-/Server-Adresse + Ports aus nginx-Connection; Übergabe per Einzelaufruf `msc_process_connection`. (Form: C-Strings + ints). 【F:src/ngx_http_modsecurity_access.c†L78-L105】【F:src/ngx_http_modsecurity_access.c†L162-L166】
5. **Request-Line-Daten**: URI/Methode/Version getrennt an `msc_process_uri`. (Form: C-Strings). 【F:src/ngx_http_modsecurity_access.c†L186-L226】
6. **Request-Header**: Iteration über nginx-Headerliste; pro Header Key/Value+Len an API. (Form: Key/Value-paarweise, nicht Gesamtblock). 【F:src/ngx_http_modsecurity_access.c†L239-L267】
7. **Request-Body-Lesen**: asynchron via `ngx_http_read_client_request_body`; bei `NGX_AGAIN` warten. (Form: event/getriebener Bufferfluss). 【F:src/ngx_http_modsecurity_access.c†L355-L371】
8. **Request-Body-Übergabe**:
   - wenn temp-file: Dateipfad an API,
   - sonst: Buffers chunk-weise (`pos..last`) an API.
   (Form: Dateipfad oder Byte-Streams). 【F:src/ngx_http_modsecurity_access.c†L394-L419】【F:src/ngx_http_modsecurity_access.c†L406-L407】
9. **Intervention-Prüfungen**: mehrfach nach Zwischenstufen über `msc_intervention`. (Form: Struct-Rückgabe). 【F:src/ngx_http_modsecurity_access.c†L179-L184】【F:src/ngx_http_modsecurity_access.c†L228-L233】【F:src/ngx_http_modsecurity_access.c†L452-L458】
10. **Response-Header-Hook**: Header einzeln + Status/HTTP-Version an libmodsecurity. 【F:src/ngx_http_modsecurity_header_filter.c†L503-L531】
11. **Response-Body-Hook**: Byte-Chunks an libmodsecurity, finale Body-Verarbeitung bei `last_buf`. 【F:src/ngx_http_modsecurity_body_filter.c†L149-L164】
12. **Log-Phase**: `msc_process_logging` auf Transaction. 【F:src/ngx_http_modsecurity_log.c†L69-L72】

# 7. Klare Abgrenzung der Verantwortlichkeiten
| Bereich | Verantwortung (aus Code/Repo) | Nicht sicher aus Repo ableitbar |
|---|---|---|
| nginx | Netzwerk/HTTP-Lifecycle/Phasen/Filterkette; stellt `ngx_http_request_t`/Headerlisten/Bufferketten bereit. | Interne nginx-Detailabläufe jenseits der aufgerufenen APIs. |
| ModSecurity-nginx-Connector | Hook-Registrierung, Config-Direktiven, Extraktion von nginx-Daten, API-Aufrufe zu libmodsecurity, Intervention in nginx umsetzen. 【F:src/ngx_http_modsecurity_module.c†L483-L624】【F:src/ngx_http_modsecurity_access.c†L46-L464】 | Vollständige Security-Entscheidungslogik. |
| libmodsecurity | Rule-Engine, Intervention-Entscheidung, Logging-/Audit-Verarbeitung (über APIs aufgerufen). 【F:src/ngx_http_modsecurity_common.h†L25-L27】【F:src/ngx_http_modsecurity_module.c†L159-L162】 | Interne Algorithmen/Regelverarbeitung im Detail (im Connector-Repo nicht vorhanden). |

# 8. Belegübersicht
- Aussage: Repo ist Connector zwischen nginx und libmodsecurity.  
  Datei/Funktion: `README.md` Einleitung.  
  Beleg: explizite Projektbeschreibung als „connection point“. 【F:README.md†L8-L13】

- Aussage: Modul nutzt Access-, Log-, Header- und Body-Hooks.  
  Datei/Funktion: `src/ngx_http_modsecurity_module.c`, `ngx_http_modsecurity_init`.  
  Beleg: Registrierung in Phasen + Filter-Init. 【F:src/ngx_http_modsecurity_module.c†L588-L621】

- Aussage: Direktiven werden im Modul registriert.  
  Datei/Struktur: `src/ngx_http_modsecurity_module.c`, `ngx_http_modsecurity_commands[]`.  
  Beleg: alle `modsecurity*`-Einträge sichtbar. 【F:src/ngx_http_modsecurity_module.c†L483-L533】

- Aussage: Request-Header werden paarweise übergeben.  
  Datei/Funktion: `src/ngx_http_modsecurity_access.c`, `ngx_http_modsecurity_access_handler`.  
  Beleg: Loop + `msc_add_n_request_header(name,len,val,len)`. 【F:src/ngx_http_modsecurity_access.c†L239-L267】

- Aussage: Request-Body wird Datei-basiert oder chunk-weise übertragen.  
  Datei/Funktion: `src/ngx_http_modsecurity_access.c`, `ngx_http_modsecurity_access_handler`.  
  Beleg: `msc_request_body_from_file` bzw. `msc_append_request_body`. 【F:src/ngx_http_modsecurity_access.c†L394-L419】【F:src/ngx_http_modsecurity_access.c†L406-L407】

- Aussage: Response-Header/-Body ebenfalls API-basiert feldweise/chunkweise.  
  Dateien/Funktionen: `src/ngx_http_modsecurity_header_filter.c` / `src/ngx_http_modsecurity_body_filter.c`.  
  Beleg: `msc_add_n_response_header`, `msc_append_response_body`. 【F:src/ngx_http_modsecurity_header_filter.c†L503-L507】【F:src/ngx_http_modsecurity_body_filter.c†L149-L150】

- Aussage: Intervention wird aus Struct gelesen und in nginx umgesetzt (Status/Redirect).  
  Datei/Funktion: `src/ngx_http_modsecurity_module.c`, `ngx_http_modsecurity_process_intervention`.  
  Beleg: `ModSecurityIntervention`-Felder und Location-Header-Setzung. 【F:src/ngx_http_modsecurity_module.c†L143-L147】【F:src/ngx_http_modsecurity_module.c†L182-L221】

- Aussage: Kein JSON-Fluss im Connector belegt.  
  Datei/Kontext: Code-Sichtung; `config` erwähnt YAJL nur Build-Linking.  
  Beleg: keine JSON-API im Connector, YAJL-Hinweise nur im Buildskript. 【F:config†L8-L23】

# 9. Unsicherheiten / nicht eindeutig belegbare Punkte
- Ob libmodsecurity intern JSON nutzt, ist aus diesem Connector-Repo **nicht eindeutig belegbar**.
- Exakte Semantik von `r->unparsed_uri` bzgl. Query ist ohne nginx-Quell-/Dokuvergleich **aus dem vorliegenden Connector-Code nicht sicher ableitbar**; separat übergeben wird Query hier jedenfalls nicht.
- Konkrete Securitywirkung bestimmter Regelsets ist **im Connector-Repo nicht eindeutig belegbar** (Enginelogik extern).
- Performanceaussagen (schneller/langsamer) sind aus den hier sichtbaren Dateien **nicht sicher ableitbar**.

# 10. TL;DR für Backend-Entwickler
- Connector-Modul in C, nicht die WAF-Engine.
- Hängt sich in Access/Log und Header-/Body-Filter ein.
- Übergibt Daten an libmodsecurity über viele einzelne C-API-Aufrufe.
- Methode/URI/Version werden separat übergeben.
- Header werden pro Header als Name/Wert+Länge übergeben.
- Body wird als Byte-Chunks oder per Dateipfad übergeben.
- Intervention kommt als C-Struct zurück und wird in nginx-Status/Redirect übersetzt.
- Buildintegration über `config`, Abhängigkeit auf `-lmodsecurity`.
- **JSON oder nicht?** Im Connector-Code ist kein JSON-Übergabepfad belegt.
- Kein einheitliches Serialisierungsobjekt sichtbar; stattdessen feldweise API-Übergabe.

# 11. Wie ich dieses Repo einem Junior-Entwickler in 2 Minuten erklären würde
Das Repo ist ein Übersetzer zwischen nginx und libmodsecurity. nginx liefert Request/Response-Daten in seinen eigenen Strukturen. Der Connector liest diese Felder, wandelt manche `ngx_str_t` in C-Strings um und ruft damit die libmodsecurity-APIs auf. Das passiert nicht als ein großes JSON-Paket, sondern in vielen einzelnen Schritten: Connection-Daten, URI/Methode/Version, Header für Header, Body chunk-weise oder aus Datei. Danach fragt der Connector die Engine nach einer Intervention. Wenn es eine gibt, setzt der Connector in nginx den passenden Effekt (z. B. Statuscode oder Redirect-Location). Die Regel- und Entscheidungslogik selbst liegt in libmodsecurity, nicht in diesem Repo. Für den Einstieg sind Moduldatei, Access-Handler und Filterdateien am wichtigsten, weil dort der komplette Datenfluss sichtbar ist.

# 12. Welche 5 Dateien ich als Erstes lesen würde und warum
1. `src/ngx_http_modsecurity_module.c` – bester Gesamteinstieg (Direktiven, Hooks, Intervention, Config-Lifecycle). 【F:src/ngx_http_modsecurity_module.c†L483-L624】
2. `src/ngx_http_modsecurity_access.c` – klarster Request-Datenfluss inkl. Datentypen/API-Aufrufe. 【F:src/ngx_http_modsecurity_access.c†L162-L267】【F:src/ngx_http_modsecurity_access.c†L394-L458】
3. `src/ngx_http_modsecurity_header_filter.c` – Response-Header-Datenfluss. 【F:src/ngx_http_modsecurity_header_filter.c†L472-L537】
4. `src/ngx_http_modsecurity_body_filter.c` – Response-Body-Chunkfluss. 【F:src/ngx_http_modsecurity_body_filter.c†L143-L175】
5. `config` – Build-/Link-Integration und Modulreihenfolge. 【F:config†L90-L161】【F:config†L164-L197】

## Direkte Antwort auf die Format-Frage
- **Wird JSON verwendet?** Im sichtbaren Connector-Code: **nicht belegt**; kein JSON-Bau/Parse-Pfad erkennbar.
- **Was stattdessen?** Feldweise, pointer-/längenbasierte C-API-Aufrufe (`msc_process_uri`, `msc_add_n_*_header`, `msc_append_*_body`, `msc_process_*`).
- **Gesammelt serialisiert oder feldweise/API-basiert?** Sichtbar ist **feldweise/API-basiert**, nicht ein einzelnes serialisiertes Austauschobjekt.
- **Sicher belegt / nicht belegt:** Belegt sind die Einzelaufrufe und Datentypen im Connector; nicht belegt sind mögliche interne Formate innerhalb von libmodsecurity.
