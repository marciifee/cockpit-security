# Deutsche Übersetzung

Diese inoffizielle Übersetzung basiert auf Bia951/cockpit-security, Commit `8f4d1e2b3f457cd57bafb2d8636ffeea40f69c53`. Die Erstellung und Überprüfung der Übersetzung wurde durch Codex unterstützt. Die ursprüngliche Software stammt aus dem Upstream-Projekt.

## Änderungen am 26. November 2026

- `src/index.html`: deutsche Texte, Formulare und Barrierefreiheitsbeschriftungen; Dokumentsprache `de`.
- `src/index.js`: deutsche Anzeige-, Bestätigungs-, Status- und Fehlertexte; übersetzte Aktionsbeschriftungen bei unveränderten technischen Werten.
- `src/manifest.json`: deutscher Menüeintrag und deutsche Suchbegriffe.
- README und ergänzende deutsche Dokumentation; ursprüngliche README unverändert archiviert.

Die chinesischen Wörter in einem regulären Ausdruck zur Erkennung externer Fehlermeldungen bleiben absichtlich erhalten. Es gibt keine Sprachumschaltung; der vorhandene `po/`-Ordner aus dem Original wird dadurch nicht zu einer aktiven Übersetzungsinfrastruktur.

## Prüfung

- JavaScript-Syntax geprüft.
- Syntaxbaumvergleich: Programmstruktur, Ausdrücke und reguläre Ausdrücke unverändert; geändert sind Texte in Strings und Template-Strings.
- 20 Vergleiche erzeugter firewalld-Befehle für Hinzufügen und Löschen erfolgreich; Laufzeit- und permanente Befehle unverändert.
- Vier vorhandene Rich Rules mit Prioritäten `-100` und `-90` erfolgreich eingelesen.
- HTML-Struktur, Element-IDs und technische Manifest-Navigation unverändert.
- Rückmeldung aus einer bestehenden Installation: Die deutsche Oberfläche wurde nach Übersetzung der tatsächlich geladenen benutzerspezifischen Kopie angezeigt.

Kein vollständiger Integrationstest aller Firewall-Backends und kein neuer Produktions-Firewalltest. Ein vollständiger npm-Build wurde in der Erstellungsumgebung nicht ausgeführt, da npm dort nicht verfügbar war. Der Buildmechanismus und die Abhängigkeiten sind unverändert aus dem Original übernommen.

## Bekannte Grenzen

Das firewalld-Formular hat kein Prioritätsfeld und gibt ohne Quell-IP einen Port auch bei ausgewähltem `drop` frei. Der deutsche Hinweis macht dies sichtbar; die Übersetzung korrigiert die ursprüngliche Firewall-Logik nicht.

## Künftige Updates

Upstream-Änderungen und deutsche Texte müssen bei Aktualisierungen zusammengeführt werden. Ein automatisches Ersetzen der Quelldateien durch neue Upstream-Dateien würde die Übersetzung überschreiben. Eine spätere Umstellung auf gettext beziehungsweise Cockpits Übersetzungsmechanismus wäre eine eigene funktionale Änderung.
