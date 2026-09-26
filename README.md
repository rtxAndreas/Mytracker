# tracker — audit Wi‑Fi local

Outil pédagogique pour tester le hotspot de l’opérateur, ou un réseau couvert
par une autorisation écrite explicite. Il ne capture pas de handshake et ne
doit pas être utilisé sur un réseau tiers.

## Utilisation

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
sudo scripts/scan_wifi.sh wlan0
sudo .venv/bin/python scripts/auth_test.py --ssid "MonWiFi" --interface wlan0 \
  --wordlist passwords.txt --limit 100
sudo scripts/attack.sh wlan0
python scripts/local_ui.py  # http://127.0.0.1:8765
```

Le tableau de bord tient sur une page desktop, détecte automatiquement les interfaces Wi-Fi puis les SSID
visibles via `nmcli`. La sélection remplit et épingle aussi le BSSID; la saisie
manuelle reste disponible si le scan n’est pas autorisé par le système.
Après confirmation, le bouton « Lancer l’audit local » exécute le test borné et
s’arrête dès que la combinaison est trouvée ou que la limite est atteinte.

`auth_test.py` respecte réellement `--interface`, résout le BSSID depuis un
scan, puis ne signale un succès que si le BSSID associé correspond. Il ne
supprime aucun profil réseau enregistré. Les échecs sont temporisés avec un
backoff borné. Les diagnostics vont sur stderr et le mot de passe trouvé seul
sur stdout.

Le générateur partagé (`scripts/charset.py`) fournit les presets et produit les
candidats paresseusement. La suite `tests/` utilise uniquement des objets Wi‑Fi
simulés; elle n’effectue aucune action radio.

## Vérification hors ligne

```bash
python3 -m compileall scripts tests
python3 -m unittest discover -s tests
```

Pour les tests réels autorisés, employer l’interpréteur `.venv/bin/python` avec
`sudo` explicite si le pilote l’exige, afin de ne pas perdre le `pywifi` du
virtualenv dans le PATH de `sudo`.
