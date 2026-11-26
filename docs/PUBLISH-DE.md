# Auf GitHub als Übersetzungs-Fork veröffentlichen

Das vorbereitete Repository ist lokal. Es wurde noch nichts in deinem GitHub-Konto angelegt oder veröffentlicht.

## Variante 1: Echter GitHub-Fork mit Originalhistorie

1. Öffne https://github.com/Bia951/cockpit-security und wähle **Fork**.
2. Wähle dein Konto. Du kannst den Namen `cockpit-security` behalten oder `cockpit-security-de` verwenden.
3. Entpacke das bereitgestellte Git-Bundle-Archiv. Klone das Bundle lokal; es enthält die Originalhistorie und den zusätzlichen Übersetzungscommit:

```bash
git clone cockpit-security-de.bundle cockpit-security-de
cd cockpit-security-de
```

4. Setze die URL deines auf GitHub erstellten Forks ein. Ersetze `DEIN-GITHUB-NAME` und gegebenenfalls den Repositorynamen:

```bash
git remote set-url origin https://github.com/DEIN-GITHUB-NAME/cockpit-security.git
git remote add upstream https://github.com/Bia951/cockpit-security.git
git push -u origin main
```

Der Push benötigt deine übliche GitHub-Anmeldung beziehungsweise SSH-/Token-Konfiguration. Falls GitHub den Push wegen neuerer Commits ablehnt, nicht mit `--force` überschreiben. Hole die neuen Commits und führe sie bewusst mit der Übersetzung zusammen.

## Variante 2: Dateien über die GitHub-Oberfläche hochladen

1. Erstelle ebenfalls einen Fork über die GitHub-Schaltfläche **Fork**.
2. Entpacke `cockpit-security-de-source.zip`.
3. Lade die Dateien und Ordner **innerhalb** des entpackten Repository-Verzeichnisses über **Add file → Upload files** in deinen Fork hoch. Nicht das ZIP und nicht den äußeren Sammelordner hochladen.
4. Prüfe im Commit-Vergleich, dass nur die drei übersetzten Quelldateien sowie README und Dokumentation geändert werden. Bei inzwischen geändertem Upstream besser nur diese Übersetzungsänderungen gezielt übernehmen.
5. Commit-Nachricht: `Add German UI translation and documentation`.

Ein bloßer Upload in ein leeres neues Repository wird von GitHub nicht automatisch als Fork des Originals verknüpft. Dafür zuerst die Fork-Schaltfläche benutzen.

## Vorschlag für die GitHub-Beschreibung

German translation of Bia951/cockpit-security – unofficial German UI for firewall and Fail2Ban management in Cockpit. Original firewall logic unchanged.

Das Originalprojekt und die Lizenz sind bereits in der README genannt. Veröffentliche Übersetzungsfehler in deinem eigenen Fork; die README des Originals bleibt unter `docs/README.upstream.md` erhalten.
