# Alisia

Mailing list server built on the [Konducta](https://github.com/mbaas2/Konducta)
framework, written in Dyalog APL.

Alisia handles subscription management, message distribution, admin commands,
GDPR compliance (audit log, DELETEME), and bounce processing for email-based
mailing lists.

## Dependencies

- **Konducta** — provides the runtime, rule engine, and `eventler_Handler` base class
- **Dyalog APL 20+** with .NET 8
- **MimeKit / MailKit** (loaded automatically via NuGet at startup)

## Deployment

Alisia is loaded by Konducta at startup via the `ALISIA_HOME` environment variable.
The deployment configuration (POP3/SMTP credentials, list names, rules) lives in a
separate config repo (e.g. **APLde-Konducta**).

## Related Repos

- **Konducta** — the event framework
- **APLde-Konducta** — APL Germany deployment configuration

## Vergleichsreport: AlisiaAlt vs Konducta-Alisia

Stand: 2026-04-16

Dieser Abschnitt fasst den Vergleich zwischen der Legacy-Variante AlisiaAlt
(Standalone-Job) und der aktuellen Implementierung als Konducta-Modul zusammen.

### Neue Funktionen in der aktuellen Implementierung

1. Multi-Instanz-Betrieb im Konducta-Framework
	- Alisia läuft als Handler-Modul und kann pro Deployment mehrfach betrieben werden.
	- Beispiel: parallele Instanzen wie Alisia_APLde und Support_APLde.

2. Erweiterte DSGVO-Funktionen
	- GetMyData, SetMyData, Deleteme inkl. Audit-Trail.
	- Deleteme anonymisiert Archivdaten und entfernt personenbezogene Einträge gezielt.

3. Verbesserte Bounce-Verarbeitung
	- NDR-Erkennung auf Regelbasis.
	- Bounce-Zähler, automatische Deaktivierung bei Schwellwert, Benachrichtigung an Admins.
	- Reset des Bounce-Zählers bei nachgewiesener aktiver Kommunikation.

4. Missbrauchsschutz durch Rate-Limiting
	- Begrenzung von Command-Frequenz pro Absender in konfigurierbarem Zeitfenster.

5. Deutlich ausgebauter Admin-Befehlssatz
	- ListMembers, Enable, Log, SetCfg, Restart.
	- Zusätzlich weiterhin die klassischen User-Befehle wie Subscribe, Unsubscribe,
	  Help, ListMsgs, GetMsgs.

6. Moderner MIME- und SMTP-Stack
	- MailKit und MimeKit statt rein legacy-orientierter POP3/SMTP-Logik.
	- Bessere Behandlung komplexer MIME-Strukturen (HTML, Inline-Images, Attachments).

7. Blacklist/Ignore-Mechanik
	- IgnoreMe und Blacklist-Verwaltung als eigene, persistente Funktion.

8. Runtime-Overrides für Konfiguration
	- Laufzeitänderungen ausgewählter Einstellungen mit Persistenz in cfg_overrides.json.

### Nicht mehr verfügbare Funktionen bzw. Legacy-Modi

1. Klassischer Standalone-Maintenance-Modus mit separatem MAINTENANCE-Passwort
	- Früherer Fluss über GETCONF, SETCONF, LISTSUB, GETTRASH, DROPTRASH, STATUS
	  als eigener Wartungskanal ist in dieser Form nicht mehr vorhanden.

2. INI-zentrierte Einzelprozess-Betriebsweise
	- Legacy-INI als primäre Betriebs- und Laufzeitsteuerung wurde durch
	  Konducta-Trigger/Rules und handler_cfg ersetzt.

3. Legacy-Adminbefehle ADDSUB, CHGSUB, DROPSUB als separates Kommando-Set
	- Funktionalität ist heute auf neue Flows verteilt, aber nicht mehr identisch
	  als alter Wartungsmodus vorhanden.

4. Exakte Legacy-STATUS/GETTRASH-Semantik
	- Funktional ersetzt durch Stats, Log und regelbasiertes Trash-Verhalten.

### Verbesserungen (qualitativ)

1. Architektur
	- Bessere Mandantenfähigkeit und sauberere Trennung von Runtime, Rules, Handler-Code,
	  Konfiguration und Deployment.

2. Security und Betrieb
	- Secrets via Umgebung und Deployment-Config statt primär statischer INI-Logik.

3. Compliance
	- DSGVO-Prozesse sind explizit und technisch nachvollziehbar implementiert.

4. Beobachtbarkeit und Betriebstransparenz
	- Ausgebautes Logging, Stats-Ausgaben und strukturierte Persistenz.

5. Zustellqualität
	- Differenziertere Bounce-Logik mit Auto-Disable/Auto-Reset.

6. Internationalisierung und Textverwaltung
	- Klar strukturierte Textressourcen (de/en) für User-, Admin- und Systemantworten.

### Schwachstellen Alt vs Neu

1. Alt: höheres Betriebsrisiko
	- Mehr Single-Process- und Legacy-Dateiflow-Abhängigkeiten.

2. Neu: höhere Komplexität
	- Mehr Features bedeuten mehr Logikpfade und größeren Testumfang.

3. Neu: filebasierte Persistenz bleibt ein Risikofaktor
	- JSON/JSONL-Dateien sind einfach und robust, aber bei parallelen Prozessen
	  ohne zusätzliche Sperr-/Transaktionsstrategie begrenzt.

4. Neu: Rate-Limit ist instanzlokal
	- Bei horizontaler Skalierung ist ohne zentrale Speicherung keine globale
	  Drosselung garantiert.

5. Neu: feste Schwellenwerte an einzelnen Stellen
	- Beispiel Bounce-Schwellwerte sollten langfristig vollständig zentral
	  konfigurierbar sein.

## Migrations-Checkliste (Alt nach Neu)

### MUSS

1. Konfigurationsmapping vollständig herstellen
	- Alle relevanten Legacy-INI-Parameter auf handler_cfg und Trigger-Config abbilden.
	- Besonders prüfen: POP3/SMTP, Admin-Konten, Attachments, Limits, Intervall, Sprache.

2. Kommandokompatibilität fachlich klären
	- Für jedes früher genutzte Kommando festlegen: direkt vorhanden, ersetzt,
	  oder bewusst entfallen.
	- Kommunikationsplan für Anwender/Admins bereitstellen.

3. Datenmigration vorbereiten
	- Subscriber-Daten, Archivdaten, Blacklist, evtl. Legacy-Statusinformationen übernehmen.
	- Datenqualität vor dem Go-Live verifizieren.

4. Sicherheits- und Secret-Konzept umstellen
	- Zugangsdaten nur noch über Environment/Deployment führen.
	- Keine produktiven Passwörter in statischen Konfigurationsdateien belassen.

5. Pflicht-Testmatrix vor Cutover
	- Subscribe, Confirm, Unsubscribe, ListMsgs, GetMsgs.
	- Bounce-Flow inkl. Disable und Enable.
	- DSGVO-Flow: GetMyData, SetMyData, Deleteme.

### SOLL

1. Betriebsmonitoring und Alarmierung aufsetzen
	- Log-Level und Auswertungen je Instanz definieren.
	- Alarmierung für SMTP/POP3-Ausfälle, Bounce-Spikes, Fehleranstieg.

2. Admin-Prozesse standardisieren
	- Nutzung von Log, Stats, ListMembers und SetCfg operational dokumentieren.

3. Last- und Abuse-Tests durchführen
	- Rate-Limit-Parameter (window/max) unter realistischen Lastprofilen validieren.

4. Rollback-Plan bereitstellen
	- Klare Entscheidungskriterien und Zeitfenster für Rückfall auf Legacy definieren.

### KANN

1. Zentrale Persistenz evaluieren
	- Mittelfristig Ablösung einzelner JSON-Dateien durch transaktionssichere Speicherung.

2. Schwellwerte stärker zentralisieren
	- Bounce- und weitere operative Grenzwerte konsequent in Konfiguration auslagern.

3. Erweiterte Regressionstests automatisieren
	- MIME/HTML-Sonderfälle, Zeichensatz-Kantenfälle, client-spezifische Mailformen.

## Empfohlene Abnahmetests

1. Funktional
	- Alle User- und Admin-Commands mit positiven und negativen Fällen.

2. Zustellbarkeit
	- Reale Testkonten über mehrere Mailprovider und Clients.
	- Prüfung von Subject, Headern, HTML/Text-Parts, Attachments, Inline-Images.

3. Compliance
	- Nachweis für Auskunft, Berichtigung/Änderung und Löschung inklusive Archivbezug.

4. Robustheit
	- Fehler in POP3/SMTP, beschädigte MIME-Mails, hohe Command-Rate, Bounce-Serien.

5. Multi-Instanz
	- Parallelbetrieb mehrerer Listen mit unterschiedlichen Konfigurationen,
	  ohne Seiteneffekte zwischen Instanzen.


