# Bedienung und technische Dokumentation

[Projektuebersicht](../README.md) · [Automation-Referenz](automation.md)

## Inhalt

- [Zweck und Umfang](#zweck-und-umfang)
- [Installation und Build](#installation-und-build)
- [Sicherheit und Grundbegriffe](#sicherheit-und-grundbegriffe)
- [Bedienung der Tabs](#bedienung-der-tabs)
- [Security settings](#security-settings)
- [Dateien und Transfergrenzen](#dateien-und-transfergrenzen)
- [Ausgabe und Fehlerdiagnose](#ausgabe-und-fehlerdiagnose)
- [Library und Firmware](#library-und-firmware)
- [Technischer Aufbau und SDK-Zuordnung](#technischer-aufbau-und-sdk-zuordnung)
- [Tests](#tests)
- [Bekannte Grenzen](#bekannte-grenzen)
- [Quellen und Lizenz](#quellen-und-lizenz)

## Zweck und Umfang

Die App stellt die AES-basierten Verwaltungsfunktionen des Windows-Demos
`uFR_AES_tester` fuer macOS bereit. Zielhardware ist der Digital Logic
**uFR nano**, Zielplattform macOS auf **Apple Silicon**.

Unterstuetzt werden Reader-Verbindung und Reader-Schluesselverwaltung,
PICC-/Application-Einstellungen, AES-Schluesselaenderungen, Standarddateien,
vollstaendiges Lesen und Hex/ASCII-Dumps sowie eine einfache Automation.
Die Oberflaeche basiert auf dem Xcode-Storyboard; Oberflaeche und
Reader-Ausgaben sind englisch.

Die Zuordnung zum Windows-Demo beschreibt die implementierten Parameter und
SDK-Aufrufe. Sie ist keine Zusicherung, dass jeder Befehl mit jeder Reader-
Firmware und jeder Kartengeneration erfolgreich ausgefuehrt werden kann.

## Installation und Build

### Voraussetzungen

| Bestandteil | Anforderung |
|---|---|
| Rechner | Mac mit Apple Silicon / ARM64 |
| Betriebssystem | macOS 14.0 oder neuer |
| Entwicklungsumgebung | Xcode mit macOS-SDK und `xcodebuild` |
| Reader | Digital Logic uFR, insbesondere uFR nano |
| Library | `libuFCoder-macos.dylib`, Version 6.0.82, ARM64 |

Der Header liegt unter `Vendor/uFCoder/include/uFCoder.h`, die Library unter
`Vendor/uFCoder/macos/arm64/libuFCoder-macos.dylib`. Xcode bindet die Library ein,
kopiert sie in `Contents/Frameworks` der App und signiert die eingebundene Kopie.
Windows-DLLs, Rosetta und eine externe OpenSSL-Installation werden nicht benoetigt.

### Release-App erstellen

Im Repository-Stamm:

```bash
xcodebuild -project "NFC Mifare DESFire Tool.xcodeproj" \
  -scheme "DESFire macOS" -configuration Release \
  -derivedDataPath build build CODE_SIGN_IDENTITY=-
```

Das Ergebnis:

```text
build/Build/Products/Release/NFC Mifare DESFire Tool.app
```

Starten:

```bash
open "build/Build/Products/Release/NFC Mifare DESFire Tool.app"
```

Alternativ das Xcode-Projekt oeffnen und das gemeinsame Scheme
**DESFire macOS** verwenden. Die angegebene Ad-hoc-Signatur ist fuer lokale
Builds geeignet. Eine Developer-ID-Signatur, Notarisierung oder ein
Installationspaket gehoeren nicht zum aktuellen Build-Ablauf.

### Reader verbinden

1. Reader per USB anschliessen und andere Programme schliessen, die ihn verwenden.
2. App starten und im Tab **Reader** auf **Connect** klicken.
3. Reader-/Library-/Firmwareinformationen in der Ausgabe kontrollieren.
4. Karte auflegen und zunaechst eine lesende Diagnose wie **Card info** ausfuehren.

Die App verbindet sich beim Start nicht automatisch. Hardware-Aktionen sind
ohne Verbindung oder waehrend einer laufenden Aktion gesperrt. Das Schliessen
des Hauptfensters beendet die App; Fensterposition und -groesse werden gespeichert.

## Sicherheit und Grundbegriffe

### Vor veraendernden Aktionen

Nur eigene oder ausdruecklich zur Administration freigegebene Karten verwenden.
Vor produktiven Aenderungen Daten und bekannte Schluessel sichern und den
Ablauf mit einer Testkarte durchspielen.

Formatieren und Loeschen entfernen Daten. Das Sperren von Schluessel- oder
Security-Einstellungen kann den spaeteren Zugriff dauerhaft ausschliessen.
**Random UID** und **Disable formatting** werden als Aktivierungen behandelt,
nicht als beliebig umschaltbare Einstellungen.

Schluessel, Reader-Passwoerter und Daten werden absichtlich im Klartext in
Eingabefeldern, Ausgabe und gegebenenfalls Automation-Scripts verwendet.
Die App speichert keine Schluessel in Preferences; Scripts werden nur auf
ausdrueckliches **Save** gespeichert. Klartext kann dennoch in exportierten
Dateien, Screenshots oder kopierten Ausgaben verbleiben.

### AID, PICC und Application

| Begriff | Bedeutung |
|---|---|
| AID | 24-Bit-Application-ID, in der GUI exakt sechs Hex-Zeichen |
| `000000` | PICC-/Kartenebene, auch als Master Application bezeichnet |
| Andere AID | Application innerhalb der Karte, etwa `F00010` |
| PICC master key | Karten-Masterschluessel, Nummer 0 |
| Application master key | Masterschluessel der jeweiligen Application, Nummer 0 |
| Application key | Schluessel innerhalb einer Application, Nummer 0 bis 13 |
| Reader slot | Speicherplatz im Reader fuer einen AES-Schluessel, Nummer 0 bis 15 |

**Reader slot und Application key sind verschieden.** Beispielsweise kann
Reader-Slot 5 den Schluessel enthalten, mit dem auf der Karte Key 0
authentifiziert wird.

Bei **Create/Delete Application** verwendet der implementierte authentifizierte
Pfad den PICC master key. Bei **Create/Delete File** wird Application-Key 0
verwendet. **Read/Write/Dump**, **Get real UID** und **Change AES key** besitzen
zusaetzlich eine explizite Application-Schluesselnummer.

### Gemeinsame Eingaben und Kurzbefehle

AID und expliziter Authentifizierungsschluessel werden zwischen **Card**,
**Applications**, **App Keys** und **Files** synchronisiert. Authentifizierungsart,
Reader-Slot und Schluesselnummer-Auswahl bleiben tabbezogen. Reader-Schluessel,
alter Zielschluessel und neuer Zielschluessel bleiben unabhaengig.

Neben den AID-Feldern setzt **PICC** die AID auf `000000`. Bis zu drei weitere
Buttons enthalten die zuletzt eingegebenen gueltigen, nicht nullwertigen AIDs.
Die Historie wird erst aktualisiert, wenn der Fokus das editierte Feld verlaesst.
Sie ist sitzungsbezogen, eindeutig und nach letzter Eingabe sortiert; die Auswahl
eines vorhandenen Buttons sortiert sie nicht um.

Schluesselgeneratoren wirken nur lokal:

| Button | Ergebnis |
|---|---|
| `0` | 16 Nullbytes |
| `1` / Ones, wo vorhanden | 16 Bytes `FF`, also binaere Einsen |
| Wuerfel | 16 zufaellige Bytes ueber `SecRandomCopyBytes` |

Die Generatoren schreiben weder einen Reader-Slot noch einen Kartenschluessel.
Nach einer Kartenschluesselaenderung werden Reader-Slots und
Authentifizierungseingaben nicht automatisch angepasst.

## Bedienung der Tabs

### Reader

| Aktion | Funktion |
|---|---|
| Connect / Disconnect | Reader oeffnen bzw. schliessen |
| Get baud rates | Aktuelle RF-Sende-/Empfangsraten lesen |
| Set baud rates | RF-Raten dauerhaft einstellen |
| Store AES key | 16-Byte-AES-Schluessel in Reader-Slot 0 bis 15 speichern |
| Lock / Unlock | Reader-Schluesselzugriff mit einem Passwort verwalten |

Reader-Passwoerter bestehen aus genau acht druckbaren ASCII-Zeichen. Das
Speichern oder Sperren eines Reader-Schluessels veraendert keinen Kartenschluessel.

RF-Codes:

| Code | Rate |
|---|---|
| 0 | 106 kbit/s |
| 1 | 212 kbit/s |
| 2 | 424 kbit/s |
| 3 | 848 kbit/s |

Welche Rate tatsaechlich unterstuetzt wird, haengt von Reader und Karte ab.

### Card

**Card info** ist eine lesende Diagnose. Sie ermittelt unter anderem Kartentyp,
Versionen, Speicherinformation und, soweit zugaenglich, PICC-Einstellungen,
Application-IDs und die reale UID. Nicht jede Karte gibt alle Informationen
ohne Authentifizierung frei. Die Diagnose kann den eingegebenen Schluessel
oder Reader-Slot und anschliessend den AES-Nullschluessel zur UID-Abfrage
verwenden; sie aendert keine Kartendaten.

**Get real UID** verwendet das AID-Feld und die darunter ausgewaehlte
Application-Schluesselnummer. Fuer PICC `000000` wird immer Key 0 verwendet.
Die reale UID ist von der waehrend der Antikollision ausgegebenen Random UID
zu unterscheiden.

**Get free memory** liest den freien Kartenspeicher.

**Format card** verwendet im normalen GUI-Pfad den AES PICC master key und
loescht die Karteninhalte. Ein Authentifizierungsfehler fuehrt nicht automatisch
zu einem Wechsel auf DES.

**Modify / Configure card** aktiviert Random UID und/oder Disable formatting.
Mindestens eine Option muss ausgewaehlt sein.

**DES to AES / Convert card master key** ist ein spezieller Fabrikkartenpfad:
Er verwendet den DES-Nullschluessel, fuehrt die vom Windows-Demo uebernommene
Konvertierung mit bis zu zehn Versuchen aus und prueft danach eine
AES-Nullschluessel-Authentifizierung. Nur verifizierter Erfolg setzt die
gemeinsamen Authentifizierungsschluesselfelder auf AES-Null und den Card-Kontext
auf PICC/Key 0. Reader-Slots bleiben unveraendert.

### Applications

Der Kontext wird ausschliesslich durch **Application ID (AID)** und die
danebenstehenden Kurzbefehle gewaehlt. Fuer `000000` zeigt die inaktive
Maximal-Key-Auswahl immer **1** an.

| Aktion | Authentifizierung / Wirkung |
|---|---|
| Create | Neue Application mit eigener Key-Anzahl und Security settings; authentifiziert mit PICC master key oder, sofern erlaubt, ohne Authentifizierung |
| Delete | Angegebene Application loeschen; implementierter Pfad verwendet PICC master key |
| Get settings | Einstellungen fuer die ausgewaehlte AID lesen, gegebenenfalls ohne Authentifizierung |
| Set settings | Gesamtes Settings-Byte mit dem Master key des gewaehlten Kontexts schreiben |

Die Key-Anzahl fuer neue Applications ist 1 bis 14. Der PICC-Kontext kann
nicht als normale Application angelegt oder geloescht werden.

Die Security-Checkboxes zeigen anfangs und nach einer AID-Aenderung einen
**Strich fuer unbekannt**. Die Key-change-Combobox ist dann ohne Auswahl.
Erfolgreiches **Get settings** fuellt die Werte; fehlgeschlagene Aktionen
lassen die aktuelle Auswahl unveraendert. **Create** und **Set settings** sind
erst verfuegbar, wenn alle anwendbaren Optionen gelesen oder ausdruecklich
gewaehlt wurden. Die Einzelbits werden unten erlaeutert.

### App Keys

**Change AES key** benoetigt den Authentifizierungsschluessel, die zur
Authentifizierung verwendete Application-Key-Nummer, die Ziel-Key-Nummer und
den neuen AES-Schluessel.

- Ziel-Key gleich Authentifizierungs-Key: `newKey` ist erforderlich; `oldKey`
  wird fuer diesen Fall nicht benoetigt.
- Ziel-Key verschieden: zusaetzlich ist der bisherige Zielschluessel
  `oldKey` erforderlich.

PICC besitzt ausschliesslich Key 0. Ein Schluesselwechsel ohne Authentifizierung
ist nicht vorgesehen. Security settings werden ausschliesslich im Tab
**Applications** verwaltet.

### Files

Dateien erfordern eine nicht nullwertige AID und eine File-ID von 0 bis 31.
**Create** legt Standarddatendateien an. Die Capacity-Eingabe wird nur fuer
die Neuanlage verwendet, nicht als angenommene Groesse bei Read oder Write.

| Aktion | Wirkung |
|---|---|
| Create | Standarddatendatei mit Kapazitaet, Kommunikationsmodus und vier Zugriffsrechten anlegen |
| Delete | Datei loeschen, authentifiziert mit Application master key oder gegebenenfalls ohne Authentifizierung |
| Write | Lokale Binaerdatei ab Offset 0 schreiben |
| Read | Gesamte Kartendatei als lokale Binaerdatei speichern |
| Dump | Gesamte Kartendatei als Hex/ASCII ausgeben |
| Get settings | Typ, Rechte, Kommunikationsmodus und gegebenenfalls Kapazitaet lesen |
| Change settings / Change access | Kommunikationsmodus und Rechte aendern |

Kommunikationsmodi:

| GUI / Script | SDK-Code | Bedeutung |
|---|---|---|
| Plain / `plain` | 0 | Unverschluesselte Datenkommunikation |
| MACing / `mac` | 1 | Datenkommunikation mit MAC |
| Enciphered / `enciphered` | 3 | Verschluesselte Datenkommunikation |

Plain bedeutet nicht automatisch freien Zugriff: Kartenrechte und
Authentifizierung bleiben relevant. Ohne Authentifizierung sind Read/Write
nur in Plain erlaubt. Die GUI schaltet bei Auswahl von No authentication
auf Plain; die Auswahl von MACing/Enciphered aktiviert einen
Authentifizierungspfad.

Jedes der Rechte `readKey`, `writeKey`, `readWriteKey` und `changeKey` hat
folgende Werte:

| Wert | Bedeutung |
|---|---|
| 0 bis 13 | Entsprechender Application-Key |
| 14 / Hex `E` | Freier Zugriff |
| 15 / Hex `F` | Zugriff nicht erlaubt |

Freier Zugriff ist ein Dateirecht, kein zusaetzlicher Authentifizierungsschluessel.
Die SDK-APIs fuer Get/Change file settings haben kein `authKeyNo`-Argument;
die Read/Write-Schluesselnummer wird fuer diese Aktionen nicht uebergeben.

### Automation

Der Tab enthaelt die Gruppe **Script** mit **Play**, **Stop**, **Save**,
**Load**, **Clear** und den editierbaren Bereich **Commands**.

Normale GUI-Aktionen werden mit Parametern als Script aufgezeichnet, auch wenn
der anschliessende Reader-Aufruf scheitert. Abgebrochene Dialoge, ungueltige
Eingaben, lokale Generatoren und interne Kapazitaetsabfragen werden nicht
aufgezeichnet. Read nimmt den Zielpfad auf; Write nimmt die Daten selbst auf.

Ein Play fuehrt das Script **einmal** aus. Fuer die naechste Karte wird sie
manuell aufgelegt und Play erneut gedrueckt. Es gibt keine Schleifen,
Variablen, Wiederholungszaehler oder automatische Kartenerkennung.

Der gesamte Scripttext wird vor dem ersten Reader-Aufruf auf Syntax,
Parameterwerte und Verbindungsreihenfolge geprueft. Kartenrechte,
Firmwareunterstuetzung und Ausgabedateien werden zusaetzlich zur Laufzeit
geprueft. Beim ersten Fehler stoppt die Ausfuehrung; fruehere Aenderungen
werden nicht zurueckgerollt.

Commands bricht lange Zeilen nicht um. Play und das Ende der Ausfuehrung
setzen die horizontale Ansicht auf Spalte 1 zurueck. Die aktive Quellzeile
wird markiert; Ergebnisse erscheinen in der normalen Ausgabebox.

Alle Befehle, Sicherheitsoptionen und Beispiele stehen in der
[Automation-Referenz](automation.md).

## Security settings

`GetKeySettings` liefert ein **ganzes Settings-Byte** sowie separat die
Key-Anzahl-/Typinformation. `ChangeKeySettings` schreibt das gesamte Byte,
keine Bitmaske einzelner Aenderungen.

### Bits 0 bis 3

Die GUI formuliert die Optionen als Einschraenkungen. Deshalb bedeutet eine
angekreuzte Checkbox jeweils **Bit = 0**, nicht Bit = 1.

| Bit / Maske | Bit = 1 | Bit = 0 / angekreuzte GUI-Einschraenkung |
|---|---|---|
| 0 / `01` | Master key kann geaendert werden | Master key nicht mehr aenderbar |
| 1 / `02` | Directory-/Settings-Abfragen ohne Master-Authentifizierung erlaubt | Abfragen benoetigen Master-Authentifizierung |
| 2 / `04` | Anlage bzw. Anlage/Loeschung ohne Master-Authentifizierung erlaubt, abhaengig vom Kontext | Master-Authentifizierung erforderlich |
| 3 / `08` | Security settings koennen mit Master-Authentifizierung geaendert werden | Security settings eingefroren |

Kontextunterschiede:

| Bit | PICC / AID `000000` | Application / AID ungleich `000000` |
|---|---|---|
| 0 | Aenderbarkeit des PICC master key | Aenderbarkeit des Application master key |
| 1 | Application-IDs und PICC-Key-Einstellungen | File-IDs und Application-/Dateieinstellungen |
| 2 | Anlegen von Applications | Anlegen und Loeschen von Dateien |
| 3 | Aenderbarkeit der PICC-Key-Einstellungen | Aenderbarkeit der Application-Key-Einstellungen |

PICC-Bit 2 erlaubt **nicht** allgemein das unauthentifizierte Loeschen von
Applications. Der implementierte Delete-Application-Pfad verwendet den
PICC master key. Directory-Zugriff gibt keine Rechte auf Dateidaten frei.
Bit 3 = 1 bedeutet ebenfalls nicht, dass Settings ohne Authentifizierung
geaendert werden duerfen.

### Bits 4 bis 7: Authentication settings for key changes

Nur fuer nicht nullwertige Applications sichtbar:

| Oberes Nibble | Regel fuer Schluesselaenderungen |
|---|---|
| `0` | Authentifizierung mit Application master key, Key 0 |
| `1` bis `D` | Authentifizierung mit dem entsprechenden vorhandenen Application-Key 1 bis 13 |
| `E` | Authentifizierung mit dem jeweils zu aendernden Key |
| `F` | Application-Keys ausser Key 0 koennen nicht geaendert werden |

Key 0 bleibt separat durch Bit 0 geregelt. Fuer PICC sind die oberen vier Bits
reserviert und werden auf 0 gehalten.

Bei Create muss ein ausgewaehlter numerischer Change-Key innerhalb der
Key-Anzahl der neuen Application liegen. Bei bestehenden Applications
prueft die Karte die tatsaechlich vorhandenen Keys; die Create-Key-Auswahl
ist keine laufende Abfrage der existierenden Application.

Beispiele:

| Settings | Bedeutung |
|---|---|
| `0F` | Alle unteren vier Bits gesetzt; Change-Key-Authentifizierung mit Master key |
| `EF` | Alle unteren vier Bits gesetzt; jeder zu aendernde Key authentifiziert sich selbst |
| `FF` | Alle unteren vier Bits gesetzt; Keys ausser Key 0 nicht aenderbar |
| `07` | Bit 3 geloescht: Settings nach dem Schreiben eingefroren |

Die Konstanten im Vendor-Header enthalten sowohl vereinfachte, gekoppelte
Varianten als auch alle 16 Kombinationen des unteren Nibbles. Die App
verarbeitet die vier unteren Bits unabhaengig und erhaelt das obere Nibble.

## Dateien und Transfergrenzen

**Create** erlaubt Kapazitaeten von 1 bis 16.777.215 Bytes, soweit die Karte
genuegend Speicher bereitstellt. **Read/Write/Dump** sind dagegen durch die
verwendete SDK-Transferschnittstelle auf 1 bis **65.535 Bytes** beschraenkt.
Zu grosse Dateien werden nicht still gekuerzt oder teilweise ausgegeben.

Write prueft die tatsaechliche Kapazitaet der Kartendatei und schreibt ab
Offset 0. Die normale GUI fuellt kuerzere Eingabedateien nicht auf:
Restbytes bleiben unveraendert. Im Script ist explizites Auffuellen mit
[`size=`](automation.md#writefile-text-und-binaerdaten) moeglich.

Read und Dump lesen die vollstaendige Datei. Die GUI speichert Read atomar
nach erfolgreichem Lesen; fehlgeschlagene Reads ersetzen keine Zieldatei.
Script-Read verwendet standardmaessig `overwrite=no`.

Die Kapazitaet wird in folgender Reihenfolge ermittelt, bis ein gueltiges
Ergebnis vorliegt:

1. SDK `GetStdFileSize` mit impliziter Key-0-Authentifizierung oder oeffentlichem Pfad.
2. SDK `GetFileSettings` mit derselben Authentifizierungsbeschraenkung.
3. Native `SelectApplication`-/`GetFileSettings`-Abfragen ohne Authentifizierung.
4. Ein-Byte-Read-Tests mit dem ausgewaehlten Transfer-Key und anschliessender
   binaerer Suche nach der Dateigrenze.

Auf Readern mit Firmware unter 5.0.76 oder unbekannter Version werden die
ersten beiden SDK-Abfragen uebersprungen. Die nativen Abfragen bzw. Read-Tests
bleiben verfuegbar. Sie umgehen keine Kartenrechte.

Die Key-0-Beschraenkung der SDK-Groessenabfrage unterscheidet sich von
Read/Write, die eine explizite Application-Schluesselnummer erhalten.
Falls keine Methode die Kapazitaet zuverlaessig ermitteln kann, stoppt der
Transfer mit einer Diagnose; die Create-Capacity-Eingabe wird nicht als
Ersatzwert verwendet.

Das Anlegen in der GUI ist auf Standarddatendateien beschraenkt.
Die Kapazitaetsabfragen koennen Standard- und Backupdatendateien erkennen;
das ist keine vollstaendige Backup-/Commit-Unterstuetzung.

## Ausgabe und Fehlerdiagnose

Jede Ausgabezeile traegt eine Rolle:

| Markierung | Bedeutung |
|---|---|
| `▶` | Befehl und Zielkontext |
| `→` | Eingabe, Authentifizierung und Parameter |
| `←` | Antwort von Reader oder Karte |
| `•` | Hinweis der App |
| `⚠` | Problem vor oder nach einem Reader-Aufruf |

Befehlstitel enthalten AID, PICC-Kontext, File-ID oder Key-Nummer, etwa
`Dump File 3 for AID F00010`. Authentifizierungszeilen beginnen mit
`Authenticate with`. Zielinformationen werden in den normalen Folgezeilen
nicht unnoetig wiederholt; Diagnosen koennen sie weiterhin enthalten.

Erfolg verlangt einen erfolgreichen Reader-Status und, soweit vorhanden,
den Kartenstatus `CARD_OPERATION_OK` / 3001. Beispiel:

```text
Status OK (3001, 12 ms)
```

Hex/ASCII-Dumps enthalten 16 Bytes pro Zeile, gruppiert in Bloecke zu acht Bytes.
Nicht druckbare Bytes ausserhalb ASCII `20` bis `7E` erscheinen in der
ASCII-Spalte als Punkt. Write zeigt die vollstaendigen Eingabedaten ebenfalls
als Hex/ASCII.

### Typische Probleme

| Problem | Einordnung / Vorgehen |
|---|---|
| Reader nicht erreichbar | USB-Verbindung pruefen; andere Reader-Programme schliessen |
| `KEY_AUTH_ERROR` / 3003 | AID, Karten-Key-Nummer, Schluesselwert und Reader-Slot unterscheiden und pruefen |
| `AUTHENTICATION_ERROR` / `91AE` | Native oeffentliche Abfrage kann durch Kartenrechte gesperrt sein |
| `UFR_COMMAND_NOT_SUPPORTED` | Reader-Firmware-/API-Unterstuetzung fehlt; kein Erfolg |
| `FILE_NOT_FOUND` | File-ID und AID kontrollieren; Diagnose kann vorhandene File-IDs nennen |
| `BOUNDARY_ERROR` | Daten-/Offsetgrenze; Read-Test-Ermittlung nutzt diesen Status intern zur Grenzbestimmung |
| Ausgabe kann nicht gespeichert werden | Pfad, Verzeichnisrechte und `overwrite` pruefen; Script stoppt ohne Rollback |

Bei Reader-Firmware **3.9.55** konnten SDK-Dateigroessen-/Settings-Abfragen
fehlschlagen, obwohl Reads mit demselben Reader-Slot funktionierten. Die
Firmwaregrenzen und vorhandenen Kapazitaetsalternativen beruecksichtigen das.

Ein beobachtetes Delete-File-Problem mit Reader-Slot 5 liess sich auch im
Windows-Demo reproduzieren: Create funktionierte mit dem Slot, Delete nicht;
mit explizitem passendem Application master key war Delete moeglich.
Die App nutzt fuer Delete bewusst die angeforderte Legacy-Funktion ohne
`_aes` und versucht nicht automatisch alternative Schluessel.

## Library und Firmware

### Eingebundene Library

Die App erwartet beim Verbinden exakt **uFCoder 6.0.82**. Eingebunden ist
`libuFCoder-macos.dylib`, nicht `libuFCoder-macos-ts.dylib`.
Die normale Library stellt die verwendeten globalen Single-Reader-Aufrufe bereit.
Alle SDK-Zugriffe der App werden auf **einer seriellen Queue** ausgefuehrt,
einschliesslich Disconnect und dem Schliessen beim Beenden.

Die `-ts`-Variante ist die thread-safe SDK-Variante fuer einen anderen
Zugriffs-/Parallelisierungsansatz. Sie ist keine Voraussetzung fuer diese
seriell arbeitende Single-Reader-App und wird nicht zusaetzlich geladen.

Library- und Reader-Firmwareversion sind voneinander unabhaengig.
Firmware wird als `major.minor.build` aus
`GetReaderFirmwareVersion` und `GetBuildNumber` ermittelt. Kann die
vollstaendige Version nicht gelesen werden, gilt sie fuer die
versionsgebundenen Buttons als unbekannt.

### Dokumentierte Mindestversionen

| Funktionsfamilie | Library mindestens | Reader-Firmware mindestens |
|---|---|---|
| `GetFileSettings` inklusive AES-/PK-/No-auth-Pfade | 5.0.89 | 5.0.76 |
| `GetStdFileSize` inklusive AES-/PK-/No-auth-Pfade | 5.0.93 | 5.0.76 |
| `ChangeFileSettings` | 5.0.96 | 5.0.81 |

Die eingebundene Library erfuellt alle drei Mindestversionen.
**Get settings** im Tab Files wird ab Reader-Firmware 5.0.76 angezeigt,
**Change settings** ab 5.0.81. Ohne Verbindung oder bei unbekannter Version
sind beide ausgeblendet. Der Backend-Pfad prueft die Grenzen auch bei
Script-Ausfuehrung.

Es gibt keine kartentypabhaengige EV3-Sperre dieser Buttons.
Der lokale Header bezeichnet `ChangeFileSettings_aes` als "Desfire EV3 only";
der zugehoerige Abschnitt der API-PDF nennt diesen Zusatz nicht.
Wegen dieser widerspruechlichen Angaben folgt die GUI nur der Reader-Firmware;
Reader/SDK/Karte entscheiden ueber den Erfolg des eigentlichen Befehls.

Weitere gepruefte Angaben:

| Angabe | Einordnung |
|---|---|
| Library 5.0.29 / Firmware 5.0.32 bei Get UID, SetConfiguration, ChangeAesKey und Read/WriteStdDataFile | Ergaenzt DESFire-Light-Unterstuetzung, keine allgemeine Mindestversion fuer alle DESFire-Karten |
| Library 5.0.97 / Firmware 5.0.81 bei `CreateAesApplication_aes_iso` | Nicht der hier verwendete nicht-ISO-Create-Pfad |
| `GetApplicationIds_aes` mit Hinweis "For uFR PLUS devices only" | Kein allgemeiner Firmware-Mindestwert; Card info nutzt native Application-ID-Abfragen |

Fuer die verwendeten Reader-Verbindungs-/Info-, Slot-/Lock-, RF-Speed-,
nativen APDU-, FreeMem-, Create/Delete-Application-, Create/Delete-Standardfile-
und Get/Change-KeySettings-Funktionen wurde in den zugehoerigen Beschreibungen
kein allgemeiner expliziter Firmware-Mindestwert gefunden. Daraus folgt
keine Zusicherung uneingeschraenkter Kompatibilitaet; es werden keine
erfundenen Versionsgrenzen eingefuehrt.

Ein automatisches Reader-Firmwareupdate findet nicht statt.

## Technischer Aufbau und SDK-Zuordnung

### Dateien

| Datei / Verzeichnis | Aufgabe |
|---|---|
| `NFC Mifare DESFire Tool/Base.lproj/Main.storyboard` | Grundlayout und vorhandene GUI-Outlets |
| `NFC Mifare DESFire Tool/ViewController.m` | GUI-Zustand, gemeinsame Eingaben, Ausgabe, Automation und Queue-Aufrufe |
| `NFC Mifare DESFire Tool/DESFireReader.h/.m` | Typisierte Requests/Results, Validierung, SDK-/Native-Aufrufe, Transfers und Diagnosen |
| `NFC Mifare DESFire Tool/DFScript.h/.m` | Recorder, Tokenisierung und Script-Validierung |
| `NFC Mifare DESFire Tool/AppDelegate.m` | Beenden nach Schliessen des Hauptfensters |
| `NFC Mifare DESFire ToolTests` | Parser-, Backend-, GUI- und Replay-Tests |
| `Vendor/uFCoder` | Unveraenderter Vendor-Header und ARM64-Library mit separater Lizenz |

Zusatzcontrols und Automation werden programmatisch an das Storyboard
angebunden. Die Hoehe des oberen Formularbereichs folgt dem Platzbedarf
des ausgewaehlten Tabs; die restliche Fensterhoehe steht der Ausgabe zur
Verfuegung. Automation nutzt die groesste Formularhoehe.

`DFRequest` kapselt Parameter und Validierung. `DFResult` kapselt Reader-,
Kartenstatus, Nutzdaten und strukturierte Rueckgabewerte. Die UI wird mit
Ergebnissen auf der Main Queue aktualisiert; der Reader-Service arbeitet
auf der seriellen Reader-Queue.

### Authentifizierungsdispatch

Die SDK-Zuordnung waehlt Reader-Slot oder expliziten AES-Schluessel:

```c
#define AUTH_CALL(name, ...) \
    (p.useInternalKey \
        ? name(p.readerKeyNumber, __VA_ARGS__) \
        : name##_PK(key, __VA_ARGS__))
```

`p` ist der bereits validierte `DFRequest`. `useInternalKey` und
`readerKeyNumber` stammen aus der GUI-Auswahl bzw. `auth=reader slot=...`.
Bei expliziter Authentifizierung stammt `p.key` aus dem Eingabefeld bzw.
`auth=aes key=...`; der Service kopiert die 16 Bytes in das lokale `key`-Array.
Die weiteren Argumente werden fuer die jeweilige Operation aus demselben
Request uebergeben. Falls ein No-auth-Pfad angeboten wird, wird er
ausdruecklich separat gewaehlt.

### Wichtige SDK-Aufrufe

`[_PK]` bezeichnet in dieser Tabelle die Wahl zwischen Reader-Slot und
externem Schluessel; es ist kein Bestandteil eines Funktionsnamens.

| Aktion | SDK / Transport |
|---|---|
| Connect / Disconnect | `ReaderOpenEx(1, "", 2, NULL)` / `ReaderClose()` |
| Store reader key | `uFR_int_DesfireWriteAesKey` |
| Lock / Unlock | `ReaderKeysLock` / `ReaderKeysUnlock` |
| RF-Raten | `GetSpeedParameters` / `SetSpeedPermanently` |
| Get real UID | `uFR_int_GetDesfireUid[_PK]` |
| Free memory | `uFR_int_DesfireFreeMem` |
| Configure / Random UID | `uFR_int_DesfireSetConfiguration[_PK]` |
| Format | `uFR_int_DesfireFormatCard[_PK]` |
| Fabrik-DES nach AES | `DES_to_AES_key_type` und AES-Null-Key-Verifikation |
| Create application | `uFR_int_DesfireCreateAesApplication[_PK]`, alternativ `_no_auth` |
| Delete application | `uFR_int_DesfireDeleteApplication[_PK]` |
| Get application settings | `uFR_int_DesfireGetKeySettings[_PK]`, alternativ `_no_auth` |
| Set application settings | `uFR_int_DesfireChangeKeySettings[_PK]` |
| Change AES key | `uFR_int_DesfireChangeAesKey[_PK]` |
| Create standard file | `uFR_int_DesfireCreateStdDataFile[_PK]`, alternativ `_no_auth` |
| Delete file | Legacy `uFR_int_DesfireDeleteFile[_PK]`, alternativ `_no_auth` |
| Read / Write | `uFR_int_DesfireReadStdDataFile[_PK]` / `uFR_int_DesfireWriteStdDataFile[_PK]`, alternativ `_no_auth` |
| File settings | `uFR_int_DesfireGetFileSettings_aes[_PK]`, alternativ `_no_auth` |
| Change file settings | `uFR_int_DesfireChangeFileSettings_aes[_PK]` |
| Capacity | SDK-Groessen-/Settings-Abfragen, native APDUs, begrenzte Read-Tests |

Card info nutzt zusaetzlich native `GetVersion`, `SelectApplication`,
`GetKeySettings` und `GetApplicationIDs` sowie `s_block_deselect`.
Die unterschiedlichen UID-Laengen aelterer Firmware werden fuer die
reale sieben Byte lange UID beruecksichtigt.

## Tests

Die Unit-Tests decken Parameter-/Settings-Validierung, Parser und Recorder,
gemischte Write-Daten, Replay, Abbruch, Dateischutz, Firmwaregrenzen,
GUI-Zustaende, AID-Historie und Layout ab. Test-Reader simulieren die
Operationen, ohne eine physische Karte zu veraendern.

```bash
xcodebuild -project "NFC Mifare DESFire Tool.xcodeproj" \
  -scheme "DESFire macOS" -derivedDataPath build \
  -destination "platform=macOS,arch=arm64" \
  -only-testing:"NFC Mifare DESFire ToolTests" \
  test CODE_SIGN_IDENTITY=-
```

Die zusaetzlichen UI-Tests benoetigen eine interaktive macOS-Sitzung mit
funktionierender UI-Automation. Ein fehlender UI-Automation-Zugang ist
kein bestandener UI-Test.

Signatur eines lokalen Builds kontrollieren:

```bash
codesign --verify --deep --strict \
  "build/Build/Products/Release/NFC Mifare DESFire Tool.app"
```

## Bekannte Grenzen

Die App ist kein allgemeines Tool fuer jeden NFC-Kartentyp.
Nicht implementiert sind unter anderem vollstaendige Verwaltungsoberflaechen
fuer Application-/File-Enumeration, Key-Versionen, beliebige
DES-/2K3DES-/3K3DES-Schluesselwechsel, Backup-/Value-/Record-Workflows mit
Commit/Abort, ISO-Identifier und erweiterte EV2-/EV3-/SDM-/Transaction-MAC-
Funktionen. Diagnosen koennen dennoch einzelne IDs oder Dateitypen anzeigen.

Alle Schreib- und Loeschvorgaenge bleiben von den tatsaechlichen
Kartenrechten abhaengig. Der frueher beobachtete
`WRONG_KEY_TYPE`-Formatierungsfehler sowie das Reader-Slot-Delete-Problem
sind nicht pauschal als geloest zu verstehen. Es gibt keine stillen
AES-/DES-Wechsel oder automatische Schluessel-Retry-Kette.

Scripts besitzen keinen Rollback und keine automatische Wiederaufnahme
nach einem Fehler. Auch nach Abbruch kann eine Karte teilweise vorbereitet sein.

## Quellen und Lizenz

- [Digital Logic: uFR API-Referenz als PDF](https://code.d-logic.com/nfc-rfid-reader-sdk/ufr-doc/-/raw/master/uFR_Series_NFC_reader_API.pdf)
- [Digital Logic: DESFire-C-Console](https://www.d-logic.com/nfc-rfid-reader-sdk/software/desfire-c-console/)
- [NXP AN11004](https://www.nxp.com/docs/en/application-note/AN11004.pdf)
- [libfreefare: DESFire-Konstanten](https://github.com/nfc-tools/libfreefare/blob/master/libfreefare/freefare.h)
- [SpringCard DESFire Tool](https://docs.springcard.com/books/Tools/PCSC_SDK/DesfireTool)
- [Vendor-Header im Repository](../Vendor/uFCoder/include/uFCoder.h)

Die gepruefte API-PDF hat Revision 2.82; die relevanten Mindestversionen stehen
dort auf Seiten 309, 322 und 326. Seitenzahlen koennen zwischen Revisionen
abweichen.

uFCoder ist eine proprietaere Library von Digital Logic.
Ihre [separate Lizenz](../Vendor/uFCoder/uFR_library_license.md) erlaubt die
Einbindung und Distribution in eigenen Projekten unter ihren Bedingungen,
beschraenkt die Nutzung jedoch auf Digital-Logic-uFR-Hardware und untersagt
eine Freigabe der Library als Open-Source-Material. Die Bereitstellung dieses
Repositorys aendert diese Bedingungen nicht.
