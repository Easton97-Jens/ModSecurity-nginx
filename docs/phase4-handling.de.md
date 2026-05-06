# ModSecurity-nginx: Phase-4-Handling (Deutsch)

## Einführung: Was ist das `phase:4`-Problem?

`phase:4`-Regeln laufen während der Verarbeitung des **Response-Bodys**. In nginx kann zu diesem Zeitpunkt der Response-Header bereits an den Client gesendet worden sein. Wenn der Header bereits gesendet wurde, kann nginx den HTTP-Status (z. B. 403) oder Redirect-Header nicht mehr zuverlässig umstellen.

In diesem Repository ist das explizit durch neue Phase-4-Mechanismen adressiert, inklusive Modi und strukturiertem Logging.

## Warum „Header bereits gesendet“ problematisch ist

Wenn eine ModSecurity-Intervention (`deny`, `status`, `redirect`) erst in `phase:4` auftritt, ist ein klassisches Blocken/Redirect nur möglich, solange Header noch nicht gesendet wurden.

Wenn Header bereits gesendet sind:

- ein späteres `status:401/403` ist nicht mehr sauber als HTTP-Status umsetzbar,
- ein späteres `redirect` (301/302 + `Location`) ist nicht mehr sauber als Redirect umsetzbar,
- nur degradierte Reaktion ist möglich (loggen, ggf. Verbindung abbrechen).

## Warum **kein globales Response-Body-Buffering** genutzt wird

Der implementierte Ansatz vermeidet globales Buffering großer Response-Bodies. Das ist konsistent mit folgenden Zielen:

- kein pauschaler Speicher-/Latenz-Overhead für alle Responses,
- keine zusätzliche Reordering-Logik zwischen bereits gesendeten Headern und späteren Body-Entscheidungen,
- keine Schein-Garantie, dass `phase:4` immer in saubere HTTP-Block-/Redirect-Semantik überführt werden kann.

## Neue Directives

### `modsecurity_phase4_mode`

Unterstützte Werte:

- `minimal`
- `safe`
- `strict`

Ungültige Werte werden in der Konfiguration abgelehnt.

### `modsecurity_phase4_content_types_file`

Lädt Content-Types aus einer Datei (eine Zeile pro Typ, `#`-Kommentare erlaubt). Einträge werden validiert; ungültige Einträge führen zu Konfigurationsfehlern.

Wenn keine Datei gesetzt ist, werden Standardtypen verwendet.

### `modsecurity_phase4_log`

Aktiviert ein separates JSON-Line-Log für Phase-4-Interventionen.

## Modi: Verhalten und Sicherheitsprofil

## `minimal`

- Bei `phase:4`-Intervention nach gesendeten Headern: **kein künstliches Blocken**, nur `log_only`.
- Ziel: minimalinvasiv, kein Verbindungsabbruch.

## `safe`

- Verhalten bei spät erkannter Intervention ebenfalls `log_only`.
- Ziel: stabiler Betrieb ohne erzwungenen Abbruch.

## `strict`

- Bei `phase:4`-Intervention nach gesendeten Headern: `connection_abort`.
- Ziel: striktere Reaktion, wenn keine saubere Status-/Redirect-Änderung mehr möglich ist.

> Wichtig: `strict` garantiert **keinen** nachträglichen 401/403/301/302-Status; es kann stattdessen zum Verbindungsabbruch kommen.

## Verhalten nach Header-Status

### Header **noch nicht** gesendet

Normale ModSecurity-Interventionspfade bleiben möglich (z. B. `deny_status`), weil nginx den Header noch anpassen kann.

### Header **bereits** gesendet

- `minimal`/`safe`: `log_only`
- `strict`: `connection_abort`

## Erklärung der Actions

### `connection_abort`

- Implementierter Fallback im `strict`-Modus bei spät erkannter `phase:4`-Intervention.
- Technisch: Request wird mit Fehlerpfad beendet (keine nachträgliche Header-Umschreibung).

### `log_only`

- Intervention wird protokolliert, aber Response-Fluss bleibt (so weit möglich) bestehen.
- Dient Nachvollziehbarkeit ohne erzwungenen Transportabbruch.

## Content-Type-Scoping (`modsecurity_phase4_content_types_file`)

Phase-4-Handling wird über Content-Type eingeschränkt. Wenn `Content-Type` fehlt oder nicht in Scope ist, wird statt harter Aktion protokolliert (`log_only`, z. B. Grund `content_type_missing` / `content_type_not_in_scope`).

Das reduziert unerwartete Effekte auf nicht-zielgerichtete Antworttypen.

## Logging

### `modsecurity_phase4_log`

Schreibt JSON-Zeilen mit Feldern wie:

- `event` (`phase4_intervention`)
- `uri`, `method`
- `response_status`, `waf_status`
- `content_type`
- `header_sent` (Boolean)
- `mode`
- `wanted_action`, `actual_action`
- `reason`
- `intervention`
- `rule_id`

### `nginx error.log`

Zusätzlich wird insbesondere im `strict`-Pfad eine Warnung ins nginx-Error-Log geschrieben, wenn nach gesendeten Headern eine Intervention eintritt.

## Sicherheitsaspekte (Implementierungsentscheidungen)

- **Keine Response-Bodies im Phase-4-Log**: reduziert Risiko von Datenabfluss über Logs.
- **Keine `ngx_chain_t`-Rewrites**: vermeidet komplexe, fehleranfällige Manipulation bereits laufender Body-Ketten.
- **Keine künstliche Reordering-Logik**: verhindert inkonsistente Zustände zwischen bereits gesendeten Headern und späteren Blockentscheidungen.
- **`strict` kann Verbindung abbrechen**: bewusster Trade-off für „fail closed“-ähnliche Reaktion ohne falsche HTTP-Status-Versprechen.

## Beispielkonfigurationen

Siehe:

- `docs/examples/phase4-minimal.conf`
- `docs/examples/phase4-safe.conf`
- `docs/examples/phase4-strict.conf`
- `docs/examples/phase4-content-types.conf`

## JSON-Log-Beispiele

`log_only` (z. B. `safe`):

```json
{"event":"phase4_intervention","uri":"/phase4","method":"GET","response_status":200,"waf_status":403,"content_type":"text/html","header_sent":true,"mode":"safe","wanted_action":"deny","actual_action":"log_only","reason":"mode_safe","intervention":"...","rule_id":"910002"}
```

`connection_abort` (`strict`):

```json
{"event":"phase4_intervention","uri":"/phase4","method":"GET","response_status":200,"waf_status":403,"content_type":"text/html","header_sent":true,"mode":"strict","wanted_action":"deny","actual_action":"connection_abort","reason":"headers_already_sent","intervention":"...","rule_id":"910003"}
```

> Feldwerte hängen vom konkreten Request/Rule-Match ab.

## Einschränkungen / bekannte Grenzen

- `phase:4` kann **nicht** garantieren, dass ein gewünschter Block-/Redirect-Status noch als HTTP-Status beim Client ankommt.
- Bei bereits gesendeten Headern ist nur degradierte Reaktion möglich (`log_only` oder `connection_abort`).
- Content-Type-Scoping ist entscheidend; Out-of-Scope-Responses werden nicht „hart“ behandelt.

## Hinweise für Betreiber

1. `phase:4` nicht als alleinigen Mechanismus für harte Zugriffskontrolle planen.
2. Für harte Block-/Redirect-Entscheidungen möglichst frühere Phasen bevorzugen.
3. `modsecurity_phase4_log` aktivieren und regelmäßig auswerten.
4. `modsecurity_phase4_content_types_file` bewusst auf sensible MIME-Typen begrenzen.
5. `strict` nur einsetzen, wenn Verbindungsabbrüche betrieblich akzeptabel sind.
