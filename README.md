# MIFARE DESFire Card Programmer for uFR

Native macOS-App zum Lesen, Beschreiben und Verwalten von MIFARE-DESFire-Karten
mit einem **Digital Logic uFR nano**. Die App orientiert sich am Windows-Tool
**uFR_AES_tester / DESFire Demo Tool** und bietet eine grafische Oberflaeche
sowie aufzeichenbare, editierbare Automation-Scripts.

## Voraussetzungen

- Apple Silicon und macOS **14 oder neuer**.
- Xcode mit macOS-SDK.
- Digital Logic uFR-Reader; eingebunden ist **uFCoder 6.0.82 fuer ARM64**.

## Bauen und starten

```bash
xcodebuild -project "NFC Mifare DESFire Tool.xcodeproj" \
  -scheme "DESFire macOS" -configuration Release \
  -derivedDataPath build build CODE_SIGN_IDENTITY=-

open "build/Build/Products/Release/NFC Mifare DESFire Tool.app"
```

Die Ad-hoc-Signatur dient dem lokalen Build, nicht einer notarisierten
Distribution. Nach dem Start im Tab **Reader** verbinden.

## Dokumentation

- [Bedienung, Sicherheit, Firmware und technische Details](doc/README.md)
- [Automation: Syntax, alle Befehle und Beispiele](doc/automation.md)
- [Hinweise und Lizenz des uFCoder-SDK](Vendor/uFCoder/README.txt)

**Achtung:** Formatieren, Loeschen und Schluessel-/Rechteaenderungen koennen
Daten oder Zugriff dauerhaft verlieren lassen. Ausgaben und Scripts enthalten
Schluessel, Passwoerter und Nutzdaten im Klartext; keine produktiven Geheimnisse
in dieses Repository einchecken. Das proprietaere SDK unterliegt der
[Digital-Logic-Lizenz](Vendor/uFCoder/uFR_library_license.md) und ist nicht
unter einer Open-Source-Lizenz freigegeben.
