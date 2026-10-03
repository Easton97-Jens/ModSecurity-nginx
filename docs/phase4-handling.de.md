# ModSecurity-nginx: Phase-4-Handling (Deutsch)

## 1) Geltungsbereich und Herkunft

Phase 4 prüft den Response-Body. nginx kann bereits Header oder Body-Bytes
gesendet haben, wenn eine Phase-4-Regel einen Deny-Status oder Redirect
anfordert. Eine späte Intervention kann den bereits beim Client angekommenen
HTTP-Status nicht zuverlässig ersetzen.

Dieser Branch übernimmt die relevante nginx-Implementierung aus
[Easton97-Jens/ModSecurity-conector, Commit b0f3bdab429717b5b0311c30c5b4d1153c672ac0](https://github.com/Easton97-Jens/ModSecurity-conector/tree/b0f3bdab429717b5b0311c30c5b4d1153c672ac0/connectors/nginx/src).
Sie wird an dieses eigenständige Modul angepasst; das Phase-4-JSON-Lines-Schema
dieses Branches bleibt erhalten. Die Multi-Connector-Laufzeit und
Laufzeitnachweise des Quellrepositories werden nicht übernommen.

Dieses Dokument beschreibt das Verhalten im Quellcode. Es behauptet nicht,
dass Laufzeit-, Protokoll- oder Integrationstests für diese Migration bestanden
wurden.

## 2) Konfiguration und inkompatible Änderungen

Alle drei Connector-Direktiven gelten in `http`-, `server`- und
`location`-Kontexten und werden vom umgebenden Kontext geerbt.

| Direktive | Werte | Standard |
| --- | --- | --- |
| `modsecurity_phase4_mode` | `off`, `safe`, `strict` | `off` |
| `modsecurity_phase4_body_limit` | Positive Byte-Anzahl oder nginx-Größe, z. B. `256k`, `2m` | `1m` (1 MiB) |
| `modsecurity_phase4_log` | Dateipfad für Phase-4-JSON-Lines-Ereignisse | Kein dediziertes Log |

Bei der Migration der bisherigen `master-phase4`-Konfiguration sind diese
Änderungen erforderlich:

- `minimal` ist nicht mehr gültig und kein Alias für `off`.
- Der Standardmodus wechselt von `safe` auf `off`. Für die zusätzliche
  Connector-Behandlung muss `safe` oder `strict` explizit gesetzt werden.
- `modsecurity_phase4_content_types_file` entfällt und verursacht einen
  nginx-Konfigurationsfehler. Die MIME-Auswahl gehört jetzt in ModSecurity-Regeln.
- Das positive Connector-Body-Budget ist neu. Bei `safe` oder `strict` muss
  ein passender Wert für die Antworten gewählt werden; null ist ungültig.

Die migrierte Konfiguration vor dem nginx-Reload mit `nginx -t` in der
Zielumgebung prüfen.

## 3) Modusverhalten und Header-Zeitpunkt

`off` deaktiviert die zusätzliche Phase-4-Interventionsbehandlung und das
Body-Budget des Connectors. Es **deaktiviert weder ModSecurity** noch die
Response-Body-Prüfung oder Phase-4-Regeln. Die native Interventionsbehandlung
bleibt aktiv. Tritt eine native Intervention nach dem Header-Versand auf,
kann die Finalisierung einen Transportfehler verursachen; `off` garantiert
keine vollständige Auslieferung jeder Antwort.

Für die zusätzliche Behandlung in `safe` und `strict` gilt:

| Header-Zustand | `safe` | `strict` |
| --- | --- | --- |
| Header noch nicht gesendet | Status/Redirect über den normalen Interventionspfad anwenden; als `deny_status` geloggt | Gleiches Verhalten |
| Header bereits gesendet | Intervention als `log_only` protokollieren und fortfahren | `connection_abort` protokollieren und die Antwort abbrechen |

`safe` degradiert nur späte **Interventionen**. Fehler der Engine-API,
ungültige Buffer, fehlgeschlagene Dateizugriffe, Speicherallokationsfehler,
Zählerüberläufe und überschrittene Body-Budgets bleiben Fehler. Sie werden
nicht in erfolgreiche Weiterleitung umgewandelt.

`strict` kann eine abgeschnittene Antwort oder einen Transportfehler beim
Client/Proxy auslösen. Nach dem Header-Versand garantiert es keinen sauberen
403-, 401-, 301- oder 302-Status. Bereits weitergeleitete Body-Bytes lassen
sich nicht zurückholen.

## 4) Response-Body-Budget und Streaming

`modsecurity_phase4_body_limit` ist in `safe` und `strict` ein
Connector-Budget für die kumulativ gesehenen Response-Bytes, einschließlich
dateibasierter Buffer. Es ist unabhängig von `SecResponseBodyLimit` der
Engine und zählt nicht nur die Bytes, die die Engine zur Prüfung speichert.

Eine Antwort darf das Budget exakt erreichen. Ein Chunk, der es überschreiten
würde, wird **vor seiner Weiterleitung** abgewiesen. Frühere Chunks können
bereits beim Client angekommen sein; ein ersetzender HTTP-Fehlerstatus ist
daher nicht garantiert. In `off` wird das konfigurierte Connector-Budget
ignoriert, die kumulative Zählung weist Überläufe über `SIZE_MAX` aber weiterhin
ab.

Der Connector puffert Antworten nicht global und ordnet nginx-Body-Ketten nicht
um. Speicherbuffer werden direkt geprüft. Rein dateibasierte Buffer werden
über einen auf 32 KiB begrenzten Arbeitsbuffer gelesen, ohne die ganze Datei
in den Speicher zu laden oder die ausgehende Originalkette zu ersetzen. Echte
Verarbeitungs- oder I/O-Fehler stoppen die betroffene Antwort.

Der Response-Body wird pro Transaktion genau einmal finalisiert: Beim
Hauptrequest wird `last_buf` ausgewertet, beim Subrequest `last_in_chain`.
Wiederholte Filteraufrufe nach der Finalisierung führen Phase 4 nicht erneut
aus.

## 5) MIME-Auswahl durch ModSecurity

Die Engine entscheidet über die Response-Body-Prüfung anhand von
`SecResponseBodyAccess`, `SecResponseBodyMimeType` und
`SecResponseBodyMimeTypesClear`. Es gibt keine Connector-Content-Type-Liste
und keine MIME-basierte Degradierung durch den Connector.

Beispielsweise die MIME-Liste in einem Regel-Ladevorgang zurücksetzen und
die ausgewählten Typen in einem getrennten Ladevorgang hinzufügen:

```nginx
modsecurity_rules 'SecResponseBodyMimeTypesClear';
modsecurity_rules '
    SecResponseBodyAccess On
    SecResponseBodyMimeType text/html text/plain application/json
';
```

Das Zurücksetzen erfolgt getrennt, weil die
[Merge-Implementierung von libModSecurity](https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/headers/modsecurity/rules_set_properties.h)
MIME-Werte entfernen kann, die im selben Regel-Ladevorgang hinzugefügt werden.

Das eigenständige [Engine-MIME-Beispiel](examples/phase4-engine-mime.conf)
enthält MIME-Ergänzungen und aktiviert die Response-Body-Prüfung. Es ist eine
ModSecurity-Regeldatei, kein nginx-Include. Um die MIME-Liste der Engine durch
diese Datei zu ersetzen, zuerst das Zurücksetzen und dann die Datei zusätzlich
zu den anderen Regeln laden:

```nginx
modsecurity_rules 'SecResponseBodyMimeTypesClear';
modsecurity_rules_file /etc/modsecurity/phase4-engine-mime.conf;
```

Die vollständigen nginx-Beispiele unten konfigurieren die MIME-Auswahl inline
mit derselben Reihenfolge getrennter Ladevorgänge.

Die Engine-Auswahl deaktiviert das unabhängige Connector-Body-Budget in
`safe` oder `strict` nicht.

## 6) Logging-Format und Sicherheitsgrenze

`modsecurity_phase4_log` erhält das bisherige JSON-Lines-Schema der
Interventionsereignisse:

- `event` (`phase4_intervention`), `uri`, `method`;
- `response_status`, `waf_status`, `content_type`, `header_sent`, `mode`;
- `wanted_action`, `actual_action`, `reason`;
- `intervention`, `rule_id`.

Die Werte von `actual_action` bleiben `deny_status`, `log_only` und
`connection_abort`; `mode` nutzt die aktuellen Modusnamen. Die
Interventionsnachricht wird maskiert, statt aus der Engine kopiert zu werden,
und das Ereignis enthält keine hinzugefügten Response-Body-Inhalte. Das
nginx-Error-Log kann weitere Diagnosen enthalten.

`off` nutzt die native Interventionsbehandlung und erzeugt diese dedizierten
Policy-Ereignisse nicht. Ein dediziertes Interventionsereignis ist keine
vollständige Erfassung aller Engine-, Buffer- oder I/O-Fehler.

## 7) Konfigurationsbeispiele und Verifikation

- [off](examples/phase4-off.conf): native Interventionsbehandlung bei
  eingeschalteter Engine-Prüfung.
- [safe](examples/phase4-safe.conf): explizite späte `log_only`-Behandlung und
  1 MiB Connector-Budget.
- [strict](examples/phase4-strict.conf): später Verbindungsabbruch und
  1 MiB Connector-Budget.
- [Engine-MIME-Auswahl](examples/phase4-engine-mime.conf):
  ModSecurity-Konfiguration für den Response-Body.

Die nginx-Beispiele verwenden `location /` und einen Beispiel-Upstream unter
`127.0.0.1:8081`. Listen-Adresse, Upstream, Logpfad und Regeln an die
Zielumgebung anpassen. Die Regel mit `sensitive-marker` dient zur Illustration.

Repository-Testendpunkte wie `/phase4` sind Testfixtures, keine erforderlichen
Produktionspfade. Laufzeitprüfungen sollten späte Deny-/Redirect-Interventionen,
HTTP/1.1 und HTTP/2, dateibasierte Antworten, Subrequests, wiederholte
Finalisierung, Budgetgrenzen und Fehlerpfade abdecken. Ergebnisse aus einem
anderen Repository oder Build belegen diese Eigenschaften des eingesetzten
Moduls nicht.
