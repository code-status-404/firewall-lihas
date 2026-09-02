# Dynamische DNS-Regeln

`firewall-lihasd.pl` hält IPv4-Regeln mit Zielen oder Quellen der Form
`dns-HOSTNAME` aktuell. Die Auflösung geschieht zur Laufzeit, damit Änderungen
innerhalb der DNS-TTL ohne vollständige Neukonfiguration wirksam werden.

## Wo `dns-HOSTNAME` verwendet werden kann

DNS-Namen können direkt an Stellen stehen, aus denen der Firewall-Generator
eine `-s dns-HOSTNAME`- oder `-d dns-HOSTNAME`-Regel erzeugt. Dazu gehören
insbesondere `interface-*/privclients`, `reject`, `nolog`, deren Includes und
`groups/hostgroup-*`.

Der Daemon liest primär die vom Generator erzeugten Dateien
`/var/lib/firewall-lihas/dns-{raw,filter,mangle,nat}`. Dadurch ist nicht mehr
entscheidend, in welcher Quelldatei ein Name stand. Hostgruppen bleiben aus
Kompatibilitätsgründen eine zusätzliche Quelle.

Namen können außerdem explizit vorgewärmt werden:

```xml
<dns active="1" refresh_dns_minimum="30" refresh_dns_config="300"
     ttl_minimum="5" max_stale="3600" retry_maximum="300"
     cname_max_depth="8">
  <host name="service.example.org"/>
</dns>
```

## CNAME- und TTL-Verhalten

CNAME-Ketten werden bis zu ihren finalen IPv4-A-Records verfolgt. In die
Datenbank und in iptables gelangen nur syntaktisch gültige IPv4-Adressen. Fehlt
der terminale A-Record in der ersten Antwort, fragt der Daemon das CNAME-Ziel
gesondert ab. Schleifen und überlange Ketten werden abgebrochen.

Als Gültigkeitsdauer gilt die kleinste TTL der CNAME-Kette und des A-Records.
`ttl_minimum` verhindert, dass eine zulässige TTL von null intern zugleich als
„Record entfernt“ interpretiert wird.

## Fehlerverhalten

`NXDOMAIN` und eine erfolgreiche Antwort ohne A-Record entfernen die bisherige
Adressmenge. Bei Timeout, `SERVFAIL` oder `REFUSED` bleiben die zuletzt
erfolgreich aufgelösten Adressen vorübergehend erhalten. `max_stale` begrenzt
diese Schonfrist nach Ablauf der ursprünglichen TTL. Wiederholte temporäre
Fehler werden mit exponentiellem Backoff bis `retry_maximum` erneut versucht.

Ein Firewall-Reload erfolgt nur, wenn sich die IP-Menge tatsächlich ändert. Der
erzeugte Regelsatz wird vor dem Einspielen mit `iptables-restore --test`
validiert. Fehler lassen den aktiven Regelsatz unverändert.

## Parameter

| Attribut | Bedeutung | Vorgabe |
|---|---|---:|
| `active` | dynamische DNS-Verarbeitung aktivieren | `1` |
| `refresh_dns_minimum` | Prüfintervall und Vorlauf vor TTL-Ablauf | `30` s |
| `refresh_dns_config` | Intervall zum erneuten Einlesen der Regelquellen | `300` s |
| `ttl_minimum` | kleinste intern verwendete TTL | `5` s |
| `max_stale` | maximale Weiterverwendung nach TTL bei temporären Fehlern | `3600` s |
| `retry_maximum` | Obergrenze des Fehler-Backoffs | `300` s |
| `cname_max_depth` | maximale Zahl verfolgter CNAME-Verweise | `8` |

`active="0"` deaktiviert DNS-Abfragen und DNS-bedingte Firewall-Reloads.
