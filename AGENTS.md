# tracker — règles de travail

Ce projet sert uniquement à l’audit pédagogique du hotspot local de l’opérateur,
ou d’un réseau couvert par une autorisation écrite explicite. Aucun test ne doit
viser un réseau tiers.

## Composants

- `scripts/scan_wifi.sh [interface]` liste les points d’accès visibles.
- `scripts/gen_passwords.py` produit paresseusement des candidats sur stdout.
- `scripts/auth_test.py` teste un flux de candidats sur un SSID autorisé, après
  résolution et vérification du BSSID. Il ne capture pas de handshake.
- `scripts/attack.sh [interface]` orchestre le flux interactif et exige une
  confirmation d’autorisation avant tout essai d’authentification.
- `scripts/local_ui.py` sert un tableau de bord limité à `127.0.0.1:8765`.

## Installation et usage

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
sudo .venv/bin/python scripts/auth_test.py --help
sudo scripts/scan_wifi.sh wlan0
sudo scripts/attack.sh wlan0
python scripts/local_ui.py
```

Le `sudo` est nécessaire uniquement lorsque le pilote ou l’outil de scan le
requiert. Utiliser explicitement `.venv/bin/python` évite le problème de PATH de
`sudo`. Ne jamais utiliser `sudo` pour les tests unitaires.

## Garanties de sécurité

`auth_test.py` respecte `--interface`, ne supprime aucun profil réseau, réutilise
un seul profil temporaire, vérifie le BSSID associé avant d’annoncer un succès,
et applique un backoff borné après les échecs. Les diagnostics vont sur stderr;
seul le mot de passe trouvé va sur stdout. Le générateur conserve la gestion de
SIGPIPE.

Les tests sont hors ligne et utilisent une couche Wi-Fi simulée. Ne pas lancer
les scripts d’authentification contre un réseau réel comme test automatisé.
