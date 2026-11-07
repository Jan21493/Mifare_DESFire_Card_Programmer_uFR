# Automation-Scripts

[Projektuebersicht](../README.md) · [Bedienung und technische Details](README.md)

## Inhalt

- [Ablauf und Sicherheitsverhalten](#ablauf-und-sicherheitsverhalten)
- [Syntax](#syntax)
- [Authentifizierung](#authentifizierung)
- [Parameterwerte](#parameterwerte)
- [Befehlsreferenz](#befehlsreferenz)
- [WriteFile: Text und Binaerdaten](#writefile-text-und-binaerdaten)
- [ReadFile: Ausgabepfad und overwrite](#readfile-ausgabepfad-und-overwrite)
- [Beispiele](#beispiele)
- [Fehler und erneute Ausfuehrung](#fehler-und-erneute-ausfuehrung)

## Ablauf und Sicherheitsverhalten

GUI-Operationen erscheinen mit ihren Parametern im editierbaren Bereich
**Commands**. Write zeichnet die importierten Daten auf, nicht den lokalen
Quelldateinamen. Read zeichnet den absoluten Zielpfad mit `overwrite=no` auf.
Die Aufzeichnung enthaelt auch Befehle, deren eigentlicher Reader-Aufruf
anschliessend fehlschlaegt.

| Button | Verhalten |
|---|---|
| Play | Gesamtes Script pruefen und genau einmal von oben nach unten ausfuehren |
| Stop | Nach dem laufenden Befehl stoppen; waehrend Pause sofort |
| Save | Script als UTF-8-Datei speichern; Warnung vor Klartextdaten |
| Load | Script nach Bestaetigung laden, niemals automatisch ausfuehren |
| Clear | Script nach Bestaetigung verwerfen |

Abgebrochene Dialoge, ungueltige GUI-Eingaben, lokale Schluesselgeneratoren
und interne Groessenabfragen werden nicht aufgezeichnet. Replay zeichnet sich
nicht erneut auf und veraendert den Scripttext nicht.

**Ein Play entspricht einer Karte.** Die naechste Karte manuell auflegen und
Play erneut druecken. Es gibt keine Variablen, Schleifen, `runs`-Option,
automatische Kartenerkennung oder automatische Wiederholung nach einem Fehler.

Vor dem ersten Reader-Aufruf werden Syntax, bekannte Parameter,
Wertebereiche und Verbindungsreihenfolge des gesamten Scripts geprueft.
Firmware, Kartenrechte, Kapazitaet und Dateiausgabe werden zusaetzlich
zur Laufzeit geprueft. Ein Fehler beendet den Durchlauf; bereits erfolgte
Aenderungen bleiben bestehen.

### ask

Veraendernde Befehle akzeptieren `ask=yes` oder `ask=no`.
Standard und vom Recorder ausgegebener Wert ist **`ask=yes`**.

```text
DeleteFile aid=F00010 file=0 auth=aes key=00000000000000000000000000000000 ask=yes
```

`ask=no` unterdrueckt nur die jeweilige Bestaetigung, nicht Validierung,
Kapazitaetspruefung, Firmwaregrenzen oder Fehlerbehandlung.
Abbrechen einer Bestaetigung stoppt den gesamten Durchlauf.
Bei rein lesenden Befehlen erzwingt `ask=yes` keine zusaetzliche Abfrage.

> [!WARNING]
> Scripts koennen Schluessel, Passwoerter und Daten im Klartext enthalten.
> Nicht veroeffentlichen, wenn produktive Geheimnisse enthalten sind.
> Loeschen, Formatieren und Sperren von Rechten sind nicht durch einen
> Script-Rollback abgesichert.

## Syntax

Eine Operation pro Zeile:

```text
CommandName parameter=value parameter=value
```

Command- und Parameternamen sowie symbolische Werte wie `aes`, `plain`,
`yes` und `no` sind **case-sensitive**. Hex-Ziffern koennen gross oder klein
geschrieben werden; aufgezeichnete AIDs und Bytes sind grossgeschrieben.

Leerzeilen und Kommentare werden ignoriert:

```text
# DESFire Script 1
# Ein Kommentar ueber die naechste Operation
Pause sec=0.5 # Inline-Kommentar nach einem Leerzeichen
```

`# DESFire Script 1` ist ein optionaler Kommentarheader, kein auszufuehrender
Befehl. Ein Script muss mindestens einen ausfuehrbaren Befehl enthalten.

Parameterwerte mit Leerzeichen stehen in doppelten Anfuehrungszeichen:

```text
text="Hello Card"
output="/Users/example/Documents/card data.bin"
password="Test1234"
```

Innerhalb solcher Strings sind nur diese Escapes vorgesehen:

| Script | Ergebnis |
|---|---|
| `\"` | Doppeltes Anfuehrungszeichen |
| `\\` | Backslash |

Es gibt keine `\n`-, `\r`- oder `\t`-Escapes. Steuerbytes stattdessen mit
`data=0A`, `data=0D` oder `data=09` angeben.

Unbekannte Parameter und doppelte Parameter werden abgelehnt. Nur
**`text=` und `data=` duerfen wiederholt** werden, damit ihre Reihenfolge
erhalten bleibt. Die Reihenfolge anderer Parameter ist frei.
Zwischen Parametername, `=` und Wert stehen keine Leerzeichen.

## Authentifizierung

In der Referenz bedeutet `[auth]`: Eine der folgenden Angaben ist
**erforderlich**, nicht optional. Die Klammern sind Dokumentationsnotation
und werden nicht ins Script geschrieben.

```text
auth=none
auth=reader slot=5
auth=aes key=00000000000000000000000000000000
```

| Modus | Zusaetzliche Parameter | Bedeutung |
|---|---|---|
| `auth=none` | Weder `key` noch `slot` | Kein Authentifizierungsschluessel; nur fuer erlaubte No-auth-Pfade |
| `auth=reader` | Genau `slot=0..15`, kein `key` | AES-Schluessel aus Reader-Speicher |
| `auth=aes` | Genau `key=...`, kein `slot` | Expliziter 16-Byte-AES-Schluessel |

`auth=none` ist fuer CreateApplication, GetApplicationSettings, CreateFile,
DeleteFile, GetFileCapacity, GetFileSettings, ReadFile, DumpFile und WriteFile
verfuegbar. Kartenrechte koennen den gewaehlten No-auth-Pfad dennoch ablehnen.
GetCardInfo erlaubt `auth=none` fuer seinen lesenden Diagnosepfad mit
AES-Null-Key-Versuch.

DeleteApplication, SetApplicationSettings, GetRealUID, ChangeAESKey,
FormatCard, EnableRandomUID, ConfigureCard und ChangeFileSettings
benoetigen Authentifizierung.

`slot` ist ein **Reader-Speicherindex**. `authKey` ist die zur
Authentifizierung verwendete **Application-Key-Nummer auf der Karte**.
Beispiel: `auth=reader slot=5 authKey=0` verwendet den in Reader-Slot 5
gespeicherten Wert fuer Application-Key 0.

Befehle ohne `authKey` nutzen den jeweils passenden Master-Key-Kontext.
Bei Create/DeleteApplication ist das PICC-Key 0, bei
Get/SetApplicationSettings der Master key der angegebenen AID, bei
Create/DeleteFile Application-Key 0. Get/ChangeFileSettings besitzen in der
verwendeten SDK-Signatur keinen separaten `authKey`-Parameter.

## Parameterwerte

| Parameter | Format und Bereich |
|---|---|
| `aid` | Hex ohne `0x`, 24 Bit; etwa `000000` oder `F00010`; GUI und Recorder verwenden sechs Stellen |
| `settings` | Hex ohne `0x`, `00..FF` fuer Applications; bei PICC nur `00..0F` |
| `key`, `newKey`, `oldKey` | Genau 16 Bytes als 32 Hex-Zeichen |
| `slot` | Dezimal 0 bis 15 |
| `authKey`, `changedKey` | Dezimal 0 bis 13; PICC nur 0 |
| `keys` | Dezimal 1 bis 14 |
| `file` | Dezimal 0 bis 31; Datei-AID muss ungleich 0 sein |
| `size` bei CreateFile | Dezimal 1 bis 16.777.215; tatsaechlicher Kartenspeicher begrenzt |
| `size` bei WriteFile | Dezimal, mindestens Nutzdatenlaenge, hoechstens 65.535 |
| `comm` | `plain`, `mac` oder `enciphered` |
| `readKey`, `writeKey`, `readWriteKey`, `changeKey` | Dezimal 0 bis 15; 14 = frei, 15 = verboten |
| `tx`, `rx` | Dezimal 0/1/2/3 fuer 106/212/424/848 kbit/s |
| `password` | Genau acht druckbare ASCII-Zeichen |
| `ask`, `overwrite`, `randomUID`, `disableFormatting` | `yes` oder `no` |
| `sec` | Nichtnegative Sekunden mit Dezimalpunkt, etwa `0`, `0.5`, `1`, `2.25` |
| `offset` bei WriteFile | Nur `0` |
| `output` | Absoluter Dateipfad ohne Steuerzeichen |

Bei CreateApplication muss ein in `settings` angegebener numerischer
Change-Key 1 bis 13 innerhalb der Key-Anzahl der neuen Application liegen.
Die [Settings-Bits](README.md#security-settings) werden als ganzes Byte
verarbeitet.

## Befehlsreferenz

### Reader und Ablauf

#### Pause

```text
Pause
Pause sec=1
Pause sec=0.5
```

`sec` ist optional und hat den Standardwert 1. Pause benoetigt keine
Reader-Verbindung und blockiert nicht die GUI. Stop beendet sie sofort.
Pause erkennt nicht, ob eine andere Karte aufgelegt wurde.

#### ConnectReader

```text
ConnectReader
```

Reader oeffnen und die erwartete Library sowie die Firmwareinformation
ermitteln. Benoetigt keinen `auth`-Parameter.
Die App verwendet `ReaderOpenEx(1, "", 2, NULL)`.

#### DisconnectReader

```text
DisconnectReader
```

Reader schliessen. Nachfolgende Hardware-Befehle benoetigen wieder
ConnectReader. Pause darf auch ohne Verbindung folgen.

#### StoreReaderKey

```text
StoreReaderKey slot=5 key=00000000000000000000000000000000 ask=yes
```

AES-Schluessel in Reader-Slot 0 bis 15 speichern.
Keine Aenderung eines Kartenschluessels und kein `[auth]`-Parameter.
Der Beispielwert ist ausschliesslich ein Test-/Fabrik-Nullschluessel.

#### LockReaderKeys

```text
LockReaderKeys password="Test1234" ask=yes
```

Reader-Schluesselzugriff mit einem acht Zeichen langen ASCII-Passwort
sperren. Das Beispielpasswort ist kein empfohlenes produktives Passwort.

#### UnlockReaderKeys

```text
UnlockReaderKeys password="Test1234" ask=yes
```

Reader-Schluesselzugriff mit dem passenden Passwort entsperren.

#### GetRFBaudRates

```text
GetRFBaudRates
```

RF-Sende-/Empfangsraten lesen.

#### SetRFBaudRates

```text
SetRFBaudRates tx=0 rx=0 ask=yes
```

RF-Raten dauerhaft einstellen. Codes 0 bis 3 entsprechen
106, 212, 424 und 848 kbit/s; Hardwaregrenzen bleiben relevant.

### Karte

#### GetRealUID

```text
GetRealUID aid=000000 authKey=0 [auth]
```

Reale UID nach Authentifizierung lesen, auch wenn Random UID fuer die
Antikollision aktiv ist. PICC verwendet Key 0; fuer eine andere AID wird
die angegebene Application-Key-Nummer verwendet. `auth=none` ist nicht vorgesehen.

#### GetFreeMemory

```text
GetFreeMemory
```

Freien Kartenspeicher lesen, ohne `[auth]`-Angabe.

#### GetCardInfo

```text
GetCardInfo [auth]
```

Lesende Diagnose von Kartentyp, Versionen, Speicher und soweit verfuegbar
PICC-Einstellungen, Application-IDs und realer UID. Der Diagnosepfad kann
zusaetzlich den AES-Nullschluessel versuchen. Fehlende Zugriffsrechte koennen
Teilinformationen verhindern.

#### FormatCard

```text
FormatCard keyType=aes [auth] ask=yes
```

Karte mit dem AES PICC master key formatieren.
Die eingegebene AID eines anderen Tabs spielt dabei keine Rolle.

`keyType=des` waehlt den vorhandenen Fabrik-DES-Null-Key-Pfad:

```text
FormatCard keyType=des auth=aes key=00000000000000000000000000000000 ask=yes
```

Diese Sonderform verlangt weiterhin eine syntaktisch gueltige
Authentifizierungsangabe, verwendet deren AES-/Slot-Wert aber nicht;
der Backend-Pfad ist auf den DES-Nullschluessel festgelegt.
Sie ist keine allgemeine DES-Schluesselauswahl und kein automatischer
Fallback nach AES-Fehlern.

> [!WARNING]
> FormatCard kann alle Application-/Dateidaten entfernen.
> Nur fuer bewusst freigegebene Karten ausfuehren.

#### EnableRandomUID

```text
EnableRandomUID [auth] ask=yes
```

Random UID mit dem PICC master key aktivieren. Das Script bietet keinen
entsprechenden Deaktivierungsbefehl.

#### ConfigureCard

```text
ConfigureCard randomUID=yes disableFormatting=no [auth] ask=yes
```

Random UID und/oder Formatierungssperre aktivieren. Beide Parameter sind
erforderlich; mindestens einer muss `yes` sein.
`no` bedeutet hier "nicht aktivieren", nicht "zuruecksetzen".

#### ConvertCardMasterKeyToAES

```text
ConvertCardMasterKeyToAES ask=yes
```

Spezieller Fabrikkartenpfad vom DES-Nullschluessel auf AES-Null.
Kein `[auth]`-Parameter. Die Konvertierung besitzt bis zu zehn Versuche
wie im Windows-Demo und eine anschliessende AES-Null-Key-Verifikation.
Sie ist nicht fuer beliebige bestehende Master-Schluessel gedacht.

### Applications und Keys

#### CreateApplication

```text
CreateApplication aid=F00010 settings=0F keys=3 [auth] ask=yes
```

Neue Application mit AID ungleich 0, 1 bis 14 Keys und dem vollstaendigen
Settings-Byte anlegen. Authentifizierter Pfad: PICC master key.
`auth=none` ist nur bei entsprechender PICC-Berechtigung erfolgreich.
Das Settings-Byte beschreibt die neue Application, nicht den PICC.

#### DeleteApplication

```text
DeleteApplication aid=F00010 [auth] ask=yes
```

Application mit allen zugehoerigen Daten loeschen.
Der implementierte Pfad verwendet den PICC master key.
`auth=none` und das Loeschen von `000000` sind nicht erlaubt.

#### GetApplicationSettings

```text
GetApplicationSettings aid=000000 [auth]
GetApplicationSettings aid=F00010 [auth]
```

Settings-Byte und Key-Anzahl-/Typinformation des angegebenen Kontexts
lesen. `auth=none` ist bei freigegebenen Listing-/Settings-Rechten moeglich.
Erfolgreiche Script-Ergebnisse fuellen die GUI nur, wenn deren AID dem
Script-Ziel entspricht.

#### SetApplicationSettings

```text
SetApplicationSettings aid=F00010 settings=0F [auth] ask=yes
```

Gesamtes Settings-Byte mit dem Master key des angegebenen Kontexts schreiben.
Fuer PICC ist das obere Nibble reserviert und muss 0 bleiben.
Das Loeschen von Bit 3 kann Einstellungen dauerhaft einfrieren.
Keine unauthentifizierte Variante.

#### ChangeAESKey

```text
ChangeAESKey aid=F00010 authKey=0 changedKey=0 newKey=00000000000000000000000000000000 [auth] ask=yes
```

Zielschluessel in einer Application bzw. den PICC-Key 0 aendern.
`newKey` ist immer erforderlich. Wenn `changedKey` von `authKey` abweicht,
ist zusaetzlich `oldKey=...` fuer den bisherigen Zielschluessel erforderlich.

```text
ChangeAESKey aid=F00010 authKey=0 changedKey=1 oldKey=00000000000000000000000000000000 newKey=00000000000000000000000000000000 auth=reader slot=5 ask=yes
```

Das Beispiel zeigt nur die Parameterbeziehung und belaesst den Zielschluessel
beim Nullwert. Fuer echte Provisionierung einen eigenen sicheren neuen
Schluessel verwenden und das Script vertraulich behandeln.
Authentifizierungswerte und Reader-Slots werden nicht automatisch aktualisiert.

### Dateien

#### CreateFile

```text
CreateFile aid=F00010 file=0 size=32 comm=plain readKey=14 writeKey=14 readWriteKey=14 changeKey=0 [auth] ask=yes
```

Standarddatendatei erstellen. `type=standard` ist optional; andere
Dateitypen koennen nicht angelegt werden. `size` ist die Kartenkapazitaet,
nicht die Laenge einer nachfolgenden Write-Nutzlast.
Authentifizierter Pfad: Application master key 0.

`auth=none` kann durch die Application-Security-Settings erlaubt sein.
Die vier Zugriffsrechte werden unabhaengig uebergeben.

#### DeleteFile

```text
DeleteFile aid=F00010 file=0 [auth] ask=yes
```

Datei loeschen. Der authentifizierte Pfad verwendet Application-Key 0 und
bewusst `uFR_int_DesfireDeleteFile[_PK]` ohne `_aes`.
No-auth ist nur bei passenden Application-Rechten erfolgreich.

#### GetFileCapacity

```text
GetFileCapacity aid=F00010 file=0 [auth]
```

Tatsaechliche Kapazitaet ueber SDK, native Settings oder begrenzte
Read-Tests bestimmen. Alte Firmware verhindert nicht automatisch alle
Alternativen. Kann keine Methode die Kapazitaet ermitteln, schlaegt der
Befehl fehl; die GUI-Create-Capacity wird nicht als Ersatz benutzt.

#### GetFileSettings

```text
GetFileSettings aid=F00010 file=0 [auth]
```

Dateityp, Kommunikationsmodus, Rechte und typabhaengige Einstellungen lesen.
Reader-Firmware mindestens **5.0.76**, Library mindestens **5.0.89**.
Die verwendete Library 6.0.82 erfuellt die Anforderung.

Authentifizierte SDK-Abfrage mit Application-Key 0; kein `authKey`-Parameter.
Ein verfuegbarer No-auth-Pfad bleibt von den Kartenrechten abhaengig.
Erfolgreiche Script-Ergebnisse fuellen nur zum aktuellen GUI-Ziel passende Felder.

#### ChangeFileSettings

```text
ChangeFileSettings aid=F00010 file=0 comm=plain readKey=14 writeKey=14 readWriteKey=14 changeKey=0 [auth] ask=yes
```

Kommunikationsmodus und Dateirechte aendern.
Reader-Firmware mindestens **5.0.81**, Library mindestens **5.0.96**.
Keine zusaetzliche EV3-GUI-Sperre; SDK und Karte entscheiden ueber
Unterstuetzung und Zugriffsrechte.

Die SDK-Signatur besitzt keinen separaten `authKey`-Parameter.
`auth=none` ist nicht erlaubt. `changeKey=15` kann spaetere Aenderungen
der Dateirechte dauerhaft verhindern.

#### ReadFile

```text
ReadFile aid=F00010 file=0 comm=plain authKey=0 [auth] output="/tmp/desfire-card.bin" overwrite=no
```

Gesamte Datei lesen und speichern. `output` ist erforderlich;
`overwrite=no` ist Standard. Bei `auth=none` ist nur `comm=plain` erlaubt.
Die vollstaendige Datei darf nicht groesser als 65.535 Bytes sein.
Es gibt keinen Script-Parameter fuer eine manuelle Teil-Leselaenge.

#### DumpFile

```text
DumpFile aid=F00010 file=0 comm=plain authKey=0 [auth]
```

Gesamte Datei wie ReadFile lesen, aber als Hex/ASCII ausgeben.
Kein `output`- oder `overwrite`-Parameter. Dieselben Transfergrenzen und
Authentifizierungsregeln wie ReadFile.

#### WriteFile

```text
WriteFile aid=F00010 file=0 comm=plain authKey=0 [auth] text="Hello" data=0D0A size=32 offset=0 ask=yes
```

Mindestens eine nicht leere Gesamtnutzlast aus `text` und/oder `data`
ist erforderlich. `size` und `offset=0` sind optional.
Mehrere Text-/Datenabschnitte werden in ihrer Quellreihenfolge
zusammengefuegt. Tatsaechliche Kartenkapazitaet wird unmittelbar vor
dem Schreiben geprueft.

## WriteFile: Text und Binaerdaten

`text=` akzeptiert ausschliesslich **druckbares ASCII `20..7E`**.
Unicode-Text, Zeilenumbrueche oder Steuerzeichen muessen als Bytes
ueber `data=` angegeben werden. `data=` enthaelt vollstaendige Hex-Bytepaare.

```text
WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text="Hello" data=0D0A text="Card" data=00 size=32 ask=yes
```

Die Nutzlast beginnt damit:

```text
48 65 6C 6C 6F 0D 0A 43 61 72 64 00
```

Die restlichen 20 Bytes bis zur expliziten Laenge 32 werden mit Nullbytes
gefuellt.

| Angabe | Wirkung |
|---|---|
| Mehrere `text` / `data` | In exakt dieser Reihenfolge aneinanderhaengen |
| Kein `size` | Nur die angegebenen Bytes schreiben; verbleibende Kartenbytes unveraendert |
| `size` groesser als Nutzlast | Mit Nullbytes bis zu dieser Laenge auffuellen |
| `size` kleiner als Nutzlast | Script bereits vor dem ersten Reader-Aufruf ablehnen |
| Mehr als 65.535 Bytes | Script ablehnen |
| `offset=0` | Optionaler expliziter Startoffset |
| Anderer Offset | Script ablehnen |
| Nutzlast groesser als Kartendatei | Zur Laufzeit vor Write ablehnen, keine Kuerzung |

Hex-Darstellung von UTF-8 ist moeglich, ohne `text=` auf Unicode zu erweitern.
Beispielsweise schreibt `data=C3A4` die zwei UTF-8-Bytes fuer ein kleines
a mit Umlaut.

Die GUI-Aufzeichnung zerlegt importierte Daten automatisch in druckbare
ASCII-Abschnitte fuer `text=` und andere Abschnitte fuer `data=`.
Sie setzt nicht automatisch `size`; Auffuellen ist eine ausdrueckliche
Scriptentscheidung.

## ReadFile: Ausgabepfad und overwrite

`output` muss ein absoluter Dateipfad sein; Verzeichnisse werden nicht
automatisch angelegt.

| Option | Verhalten |
|---|---|
| `overwrite=no` oder weggelassen | Vorhandene Datei nicht ersetzen |
| `overwrite=yes` | Erst nach erfolgreichem Read atomar ersetzen |

Bei `overwrite=no` schuetzt exklusive Dateierstellung auch gegen eine Datei,
die zwischen Vorpruefung und Speicherung entsteht. Ein fehlgeschlagener Read
ersetzt keine bestehende Datei.

Ein ungueltiger, belegter oder nicht beschreibbarer Pfad kann den Durchlauf
nach bereits erfolgten Kartenaenderungen stoppen. Wiederholte Kartenlaeufe
benoetigen daher einen bewusst geaenderten Zielpfad oder `overwrite=yes`.
Da es keine Variablen gibt, wird nicht automatisch ein Dateiname pro UID erzeugt.

## Beispiele

### Lesende Diagnose ohne expliziten Schluessel

```text
# DESFire Script 1
ConnectReader
GetCardInfo auth=none
GetFreeMemory
Pause sec=1
DisconnectReader
```

Die Diagnose kann trotz erfolgreicher Reader-Verbindung nicht alle
Karteninformationen ohne Rechte liefern.

### Eine Testkarte vorbereiten

> [!CAUTION]
> Dieses Beispiel legt eine Application und eine Datei mit freien
> Datenzugriffsrechten an. Es ist ein Testablauf, keine sichere
> Produktionskonfiguration. PICC-Key und Kartenrechte muessen dazu passen.

```text
# DESFire Script 1
ConnectReader
CreateApplication aid=F00010 settings=0F keys=3 auth=aes key=00000000000000000000000000000000 ask=yes
CreateFile aid=F00010 file=0 size=32 comm=plain readKey=14 writeKey=14 readWriteKey=14 changeKey=0 auth=none ask=yes
WriteFile aid=F00010 file=0 comm=plain authKey=0 auth=none text="Hello" data=0D0A text="Card" data=00 size=32 ask=yes
DumpFile aid=F00010 file=0 comm=plain authKey=0 auth=none
ReadFile aid=F00010 file=0 comm=plain authKey=0 auth=none output="/tmp/desfire-card.bin" overwrite=no
DisconnectReader
```

Die Nullschluessel sind nur Fabrik-/Testwerte. Die neue Application startet
mit AES-Null-Keys; der PICC muss fuer Create den angegebenen Schluessel
verwenden. Das Beispiel wird nicht automatisch geladen oder ausgefuehrt.
Bei einem bereits belegten Zielpfad stoppt ReadFile.

Fuer die naechste Karte manuell wechseln und Play erneut ausfuehren.
Wird im Script ConnectReader beibehalten, sorgt DisconnectReader am Ende
fuer den passenden Ausgangszustand eines erfolgreichen Durchlaufs.

### Reader-Slot fuer vorhandene Daten verwenden

Voraussetzung: Reader-Slot 5 enthaelt den richtigen Wert fuer
Application-Key 0 der Application `F00010`.

```text
ConnectReader
GetApplicationSettings aid=F00010 auth=reader slot=5
DumpFile aid=F00010 file=0 comm=plain authKey=0 auth=reader slot=5
DisconnectReader
```

Ein Slot-Script enthaelt nicht den Authentifizierungsschluessel selbst,
ist aber vom bereits korrekt programmierten Reader abhaengig.

### File settings auf neuer Firmware lesen

Voraussetzung: Reader-Firmware mindestens 5.0.76 und passender Application master key.

```text
ConnectReader
GetFileSettings aid=F00010 file=0 auth=reader slot=5
DisconnectReader
```

ChangeFileSettings ist erst ab Firmware 5.0.81 verfuegbar.

## Fehler und erneute Ausfuehrung

| Zeitpunkt | Verhalten |
|---|---|
| Syntax-/Wertefehler irgendwo im Script | Vor dem ersten Reader-Aufruf ablehnen; fehlerhafte Zeile nennen |
| Hardware-Befehl ohne Verbindung | Verbindungsreihenfolge vorab ablehnen |
| Bestaetigung abgebrochen | Script stoppen |
| Reader-/Kartenfehler | Am ersten Fehler stoppen |
| Dateischutz-/Speicherfehler | Stoppen; bestehende Datei nicht als erfolgreichen Read ersetzen |
| Stop waehrend Reader-Befehl | Laufenden Befehl beenden, danach stoppen |
| Stop waehrend Pause | Sofort stoppen |

Nicht jede Laufzeitbedingung laesst sich vorab validieren. Beispielsweise
sind Reader-Firmware, existierende Applications, Schluessel, Rechte und
freier Speicher Eigenschaften des aktuell verbundenen Readers bzw. der
aufgelegten Karte.

Nach einem Fehler kann die Karte teilweise veraendert und der Reader noch
verbunden sein. Vor erneutem Play den Zustand bewusst pruefen, insbesondere
wenn Create-, Delete-, Format- oder Schluesselbefehle enthalten sind.
Es gibt keine automatische Fortsetzung an der Fehlerzeile und keine
automatische Wiederherstellung vorheriger Daten.
