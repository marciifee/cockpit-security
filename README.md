# Cockpit Security – deutsche Übersetzung

Deutsche Übersetzung der Cockpit-Erweiterung **[Bia951/cockpit-security](https://github.com/Bia951/cockpit-security)** für Firewall- und Fail2Ban-Verwaltung.

Dies ist eine inoffizielle Übersetzungsvariante. Die ursprüngliche Anwendung und Firewall-Logik stammen aus dem Originalprojekt. Die Anpassungen betreffen die deutsche Oberfläche und Dokumentation; eine Zugehörigkeit zum offiziellen Cockpit-Projekt wird nicht behauptet.

## Umfang

- Deutscher Menüeintrag **Sicherheit**.
- Übersetzte Formulare, Dialoge, Statusanzeigen, Bestätigungen und Fehlermeldungen.
- Deutsche Beschriftungen für Allow-/Block-Aktionen; die technischen Werte wie `accept`, `drop` und `reject` bleiben unverändert.
- Zusätzlicher Formularhinweis auf die vorhandenen Grenzen der firewalld-Eingabemaske.

Die Oberfläche ist fest auf Deutsch übersetzt. Dies ist noch keine mehrsprachige Implementierung mit Sprachumschalter. Externe Systemmeldungen und die Firewall-Regeln selbst werden nicht übersetzt.

## Funktionen des Originalprojekts

Die Erweiterung erkennt firewalld, UFW, nftables und iptables. Sie zeigt Firewall-Regeln an und bietet je nach Backend Aktionen zum Hinzufügen, Löschen, Laden oder Speichern. Für firewalld werden Dienste, Ports und Rich Rules der **Standardzone** angezeigt und Laufzeit- sowie dauerhafte Konfiguration berücksichtigt.

Die Fail2Ban-Seite zeigt Dienste, Jails und gesperrte IP-Adressen an und ermöglicht Dienstaktionen sowie das Aufheben von Sperren. Änderungen benötigen Administratorrechte in Cockpit.

### Grenzen des firewalld-Formulars

Das Originalformular kann keine Prioritäten wie `-100` oder `-90` einstellen. Vorhandene Rich Rules mit Prioritäten können angezeigt werden, sollten aber nicht über dieses vereinfachte Formular nachgebaut werden.

**Ohne Quell-IP erzeugt das Originalformular immer eine Portfreigabe – auch bei ausgewähltem `drop`.** Mit Quell-IP erzeugt es eine `accept`- oder `drop`-Rich-Rule. Der deutsche Formularhinweis benennt dieses Verhalten. Dieser Übersetzungsstand ändert die Firewall-Logik nicht.

## Voraussetzungen

- Linux mit installiertem Cockpit.
- Die jeweils verwendete Firewall beziehungsweise Fail2Ban auf dem Host.
- Node.js (laut Originalprojekt mindestens Version 16), npm und make zum Bauen.

Beispiele für Build-Abhängigkeiten:

```bash
# Debian / Ubuntu
sudo apt install nodejs npm make

# Fedora / Rocky / AlmaLinux
sudo dnf install nodejs npm make

# openSUSE
sudo zypper install nodejs npm make
```

## Bauen und installieren

Lade dieses Repository über seine GitHub-Schaltfläche **Code** herunter oder klone seine eigene URL. Wechsle anschließend in das Repository-Verzeichnis:

```bash
npm ci
make build
sudo make install
```

Das installiert die Erweiterung unter `/usr/local/share/cockpit/security/`. Build und Installation können auch mit `make build` und anschließend `sudo make install` wiederholt werden. Die Abhängigkeit PatternFly wird beim Bauen in `dist/` aufgenommen.

Danach in Cockpit abmelden, erneut anmelden und die Browserseite vollständig neu laden. Die Erweiterung hat keinen eigenen systemd-Dienst. Ein Neustart der Firewall ist nicht nötig.

### Bereits vorhandene benutzerspezifische Installation

`~/.local/share/cockpit/security` kann die systemweite Kopie überlagern. Prüfe bei weiterhin chinesischer Oberfläche:

```bash
ls -ld ~/.local/share/cockpit/security
readlink -f ~/.local/share/cockpit/security
```

Wenn dieser Link auf ein altes `dist/` zeigt, muss auch dort die deutsche Variante gebaut werden oder der Link auf das `dist/` dieses Repositorys zeigen. Sichere vorhandene Anpassungen vor einem Austausch.

Für eine neue benutzerspezifische Entwicklungsinstallation bietet das Originalprojekt `make devel-install`. Dieser Befehl ersetzt den vorhandenen Eintrag `~/.local/share/cockpit/security`; daher nur bewusst verwenden. Das Quellverzeichnis muss anschließend bestehen bleiben.

## Herkunft und Änderungen

- Original: [Bia951/cockpit-security](https://github.com/Bia951/cockpit-security)
- Übersetzungsbasis: [`8f4d1e2b3f457cd57bafb2d8636ffeea40f69c53`](https://github.com/Bia951/cockpit-security/commit/8f4d1e2b3f457cd57bafb2d8636ffeea40f69c53)
- Übersetzungsstand: 26. November 2026
- [Änderungs- und Prüfhinweise](docs/TRANSLATION-DE.md)
- [Unveränderte ursprüngliche README](docs/README.upstream.md)
- [Anleitung zur Veröffentlichung als eigener GitHub-Fork](docs/PUBLISH-DE.md)

## Lizenz

Die Lizenz des Originalprojekts bleibt erhalten: **LGPL-2.1-or-later** gemäß Projektmetadaten; siehe [LICENSE](LICENSE). Die deutschen Übersetzungen und Dokumentationsanpassungen werden unter denselben Bedingungen bereitgestellt. Originale Urheberhinweise und Git-Historie bleiben erhalten.
