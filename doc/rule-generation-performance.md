# Analyse: Performance der Regelgenerierung

Stand: 2026-09-02. Dieses Dokument hält die Untersuchung fest; es beschreibt
keine bereits implementierten Optimierungen.

## Abgrenzung

Betrachtet wurden `firewall.sh`, `bin/firewall-lihas.pl` und die dynamische
DNS-Expansion. Vor Änderungen müssen die Abschnitte einzeln gemessen werden,
damit wahrgenommene Reload-Dauer und tatsächliche Generierungsdauer nicht
verwechselt werden.

Geeignete erste Vergleichswerte sind:

```shell
time service firewall-lihas test
time service firewall-lihas reload
```

Für eine genauere Messung sollten Gruppenimport, Regelexpansion, Zusammenbau
der Regeldateien, `iptables-restore --test` und `iptables-restore` getrennt
zeitlich protokolliert werden.

## Erkenntnisse und empfohlene Reihenfolge

### 1. Feste Wartezeit dominiert die sichtbare Reload-Dauer

`firewall.sh` wartet bei Start, Reload und Restart jeweils fünf Sekunden, bevor
der DNS-Daemon gestartet wird. Diese Zeit gehört nicht zur Regelgenerierung,
bestimmt aber häufig die vom Benutzer beobachtete Dauer.

Vor einer Entfernung muss geklärt werden, welchen historischen Zweck die
Wartezeit erfüllt. Falls eine Abhängigkeit abgewartet werden muss, sollte eine
konkrete Bereitschaftsprüfung die pauschale Wartezeit ersetzen.

Erwarteter Nutzen: hoch für die sichtbare Dauer, kein Einfluss auf die reine
Generierungszeit.

### 2. Kommentar-IDs innerhalb eines Laufs cachen

`firewall_comment_add_key()` fragt SQLite bei jedem Aufruf nach einer bereits
vorhandenen ID. Gruppenexpansionen können dieselbe Datei sehr oft referenzieren
und dadurch dieselbe Abfrage wiederholen.

Vorschlag: Im Prozess eine Zuordnung `Dateiname -> Kommentar-ID` führen. SQLite
wird dann je Datei höchstens einmal abgefragt. Die Datenbank bleibt weiterhin
die dauerhafte Quelle der IDs.

Erwarteter Nutzen: mittel bis hoch bei vielen Regeln oder Gruppenreferenzen;
kleine, lokal begrenzte Änderung.

### 3. DNS-Daten in `expand_dns()` nicht rekursiv kopieren

`expand_dns()` kopiert die vollständigen Hashes mit DNS-Adressen in jedem
rekursiven Schritt, obwohl sie nur gelesen werden. Bei mehreren DNS-Namen und
mehreren A-Records wächst die Zahl der Aufrufe durch das notwendige kartesische
Produkt.

Vorschlag: Die bestehenden Hash-Referenzen direkt weiterreichen. Die fachlich
notwendige Vervielfachung der Regeln bleibt erhalten, unnötige Datenkopien
entfallen.

Erwarteter Nutzen: mittel bis hoch bei umfangreichen DNS-Regeln; geringes
Änderungsrisiko.

### 4. Verzeichnisse nur einmal pro Lauf einlesen

Das Gruppenverzeichnis wird getrennt für Host-, Port- und Interfacegruppen
geöffnet. Auch das Konfigurationsverzeichnis wird mehrfach nach Interfaces und
Policy-Routing-Verzeichnissen durchsucht.

Vorschlag: Jedes Verzeichnis einmal lesen und die Einträge anschließend anhand
ihres Präfixes auf vorbereitete Listen verteilen.

Erwarteter Nutzen: eher klein; vereinfacht zugleich den Hauptablauf.

### 5. Expansionsergebnisse als Listen statt als wachsende Strings führen

Die rekursiven Expansionsfunktionen bauen große Ergebnisse wiederholt mit
String-Verkettung auf. Aufrufer teilen diese Strings anschließend erneut an
Zeilenumbrüchen. Das verursacht bei großen und verschachtelten Gruppen
zusätzliche Kopien und temporären Speicherbedarf.

Vorschlag: Intern Listen von Regelzeilen zurückgeben, mit `push` erweitern und
erst unmittelbar bei der Ausgabe zusammenfügen. Das kartesische Produkt aus
mehreren Gruppen bleibt fachlich unvermeidbar.

Erwarteter Nutzen: hoch bei großen Gruppen; mittleres Änderungsrisiko, deshalb
erst nach den lokaleren Optimierungen umsetzen.

### 6. Vollständig expandierte Gruppen optional cachen

Die Quelldateien der Gruppen werden bereits nur einmal geladen. Verschachtelte
Gruppen werden bei jeder Verwendung jedoch erneut rekursiv expandiert.

Ein zusätzlicher Cache für vollständig expandierte Gruppen kann sich lohnen,
wenn dieselbe Gruppe in vielen Regeln vorkommt. Kommentarzuordnungen und eine
Erkennung zyklischer Gruppen müssen dabei korrekt bleiben.

Erwarteter Nutzen: abhängig von der Konfiguration; erst nach Messung umsetzen,
da komplexer als ein Cache für Kommentar-IDs.

### 7. Temporäre Regeldateien in einem Durchlauf aufteilen

`firewall.sh` liest jede temporäre Tabelle zweimal: einmal für normale Regeln
und einmal für DNS-abhängige Regeln. Das betrifft raw, filter, mangle und nat
sowie entsprechende IPv6-Dateien.

Vorschlag: Eine kleine `awk`-Funktion schreibt beide Ausgaben in einem Durchlauf.
Dabei muss die bestehende Sonderbehandlung für DNAT unverändert bleiben.

Erwarteter Nutzen: klein bis mittel; vor allem weniger Prozesse und Datei-I/O.

### 8. Unnötige `cat`-Prozesse entfernen

Einige Pipelines beginnen mit `cat DATEI | ...`. Eingabeumleitungen vermeiden
diese zusätzlichen Prozesse. Das ist eine risikoarme Bereinigung, aber keine
wesentliche Einzeloptimierung.

Erwarteter Nutzen: klein.

### 9. Unveränderte vollständige Regelsätze nicht erneut einspielen

Ein Hashvergleich zwischen erzeugtem und zuletzt aktivem Regelsatz könnte
No-op-Reloads vermeiden. Dafür wäre zusätzlicher persistenter Zustand nötig;
außerdem müssen externe Änderungen an iptables berücksichtigt werden.

Empfehlung: Nur bei nachgewiesen häufigen, unveränderten Reloads verfolgen.
Diese Maßnahme hat mehr Zustands- und Fehlerrisiken als die vorstehenden
Optimierungen.

## Nicht als erste Maßnahme empfohlen

- Keine komplette Neuschreibung des Generators.
- Keine Parallelisierung der Expansion: Reihenfolge und gemeinsame Ausgaben
  machen Synchronisation aufwendiger als den erwarteten Nutzen.
- Keine Änderung des fachlich notwendigen kartesischen Produkts von Gruppen
  oder DNS-Adressen.
- Kein Cache über mehrere Läufe, bevor Invalidierung und externe Änderungen
  eindeutig definiert sind.

## Vorgeschlagene Umsetzungspakete

1. Messpunkte ergänzen und Baseline aufnehmen.
2. Fünf-Sekunden-Wartezeit klären, Kommentar-ID-Cache und DNS-Referenzen
   optimieren.
3. Verzeichnisscans zusammenführen und kleine Shell-Prozesse reduzieren.
4. Nur bei weiterhin messbarem Bedarf die listenbasierte Gruppenexpansion
   umsetzen.
5. Nach jedem Paket Regeldateien byteweise beziehungsweise semantisch mit der
   bisherigen Ausgabe vergleichen und `iptables-restore --test` ausführen.
