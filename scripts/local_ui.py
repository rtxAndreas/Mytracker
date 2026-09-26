#!/usr/bin/env python3
"""Local-only dashboard for preparing an authorised hotspot audit."""

import argparse
import json
import re
import shlex
import subprocess
import sys
import threading
import webbrowser
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from string import Template
from urllib.parse import parse_qs, urlparse


DEFAULTS = {
    "ssid": "",
    "bssid": "",
    "interface": "wlan0",
    "charset": "alphanumeric",
    "min_length": "8",
    "max_length": "8",
    "limit": "100",
    "timeout": "5",
}

INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")


def split_nmcli_line(line):
    fields = []
    current = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields


def detect_networks(interface, runner=subprocess.run):
    """List visible access points without connecting to any of them."""
    if not INTERFACE_PATTERN.fullmatch(interface):
        raise ValueError("Nom d’interface Wi-Fi invalide.")
    command = [
        "nmcli", "-t", "--escape", "yes",
        "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list",
        "ifname", interface,
    ]
    try:
        completed = runner(command, capture_output=True, text=True, timeout=12, check=True)
    except FileNotFoundError as exc:
        raise RuntimeError("nmcli n’est pas installé.") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Le scan Wi-Fi a dépassé le délai autorisé.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError((exc.stderr or "scan impossible").strip()) from exc

    networks = {}
    for line in completed.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) != 4:
            continue
        ssid, bssid, signal, security = (part.strip() for part in parts)
        if not ssid or not bssid:
            continue
        try:
            signal_value = max(0, min(100, int(signal)))
        except ValueError:
            signal_value = 0
        networks[(ssid, bssid.lower())] = {
            "ssid": ssid, "bssid": bssid, "signal": signal_value,
            "security": security or "Inconnue",
        }
    return sorted(networks.values(), key=lambda item: item["signal"], reverse=True)


def detect_interfaces(runner=subprocess.run):
    command = ["nmcli", "-t", "--escape", "yes", "-f", "DEVICE,TYPE,STATE", "device", "status"]
    try:
        completed = runner(command, capture_output=True, text=True, timeout=5, check=True)
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
        raise RuntimeError("Impossible de détecter les interfaces Wi-Fi.") from exc
    interfaces = []
    for line in completed.stdout.splitlines():
        parts = split_nmcli_line(line)
        if len(parts) == 3 and parts[0] and parts[1] in {"wifi", "802-11-wireless"}:
            interfaces.append({"name": parts[0], "state": parts[2]})
    return interfaces


def validate_config(values):
    config = {key: values.get(key, DEFAULTS[key]).strip() for key in DEFAULTS}
    if not config["ssid"]:
        raise ValueError("Le SSID est obligatoire.")
    if not config["interface"]:
        raise ValueError("L’interface Wi-Fi est obligatoire.")
    for key, label, minimum in (
        ("min_length", "Longueur minimale", 1),
        ("max_length", "Longueur maximale", 1),
        ("limit", "Limite", 1),
    ):
        try:
            number = int(config[key])
        except ValueError as exc:
            raise ValueError(f"{label} doit être un nombre entier.") from exc
        if number < minimum:
            raise ValueError(f"{label} doit être supérieure ou égale à {minimum}.")
    if int(config["max_length"]) < int(config["min_length"]):
        raise ValueError("La longueur maximale doit être supérieure ou égale au minimum.")
    try:
        if float(config["timeout"]) <= 0:
            raise ValueError
    except ValueError as exc:
        raise ValueError("Le délai doit être un nombre positif.") from exc
    if values.get("authorized") != "yes":
        raise ValueError("La confirmation d’autorisation est obligatoire.")
    return config


def build_command(config):
    command = [
        "sudo", ".venv/bin/python", "scripts/auth_test.py",
        "--ssid", config["ssid"],
        "--interface", config["interface"],
        "--charset", config["charset"],
        "--min", config["min_length"],
        "--max", config["max_length"],
        "--limit", config["limit"],
        "--timeout", config["timeout"],
    ]
    if config["bssid"]:
        command.extend(("--bssid", config["bssid"]))
    return shlex.join(command)


def build_audit_argv(config):
    script = str(Path(__file__).with_name("auth_test.py"))
    command = [sys.executable, script, "--ssid", config["ssid"],
               "--interface", config["interface"], "--charset", config["charset"],
               "--min", config["min_length"], "--max", config["max_length"],
               "--limit", config["limit"], "--timeout", config["timeout"]]
    if config["bssid"]:
        command.extend(("--bssid", config["bssid"]))
    return command


PAGE = Template(r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel — Audit Wi-Fi local</title>
<style>
:root{color-scheme:dark;--bg:#07111f;--panel:#0d1b2d;--panel2:#10243a;--line:#203a55;--text:#eef7ff;--muted:#8ba5bd;--cyan:#4de2c5;--blue:#5ca8ff;--danger:#ff7383;--shadow:0 22px 55px #02070d99}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font:15px/1.5 Inter,ui-sans-serif,system-ui,sans-serif;color:var(--text);background:radial-gradient(circle at 85% 0,#133c53 0,transparent 34rem),var(--bg)}
body:before{content:"";position:fixed;inset:0;pointer-events:none;opacity:.12;background-image:linear-gradient(#5ca8ff22 1px,transparent 1px),linear-gradient(90deg,#5ca8ff22 1px,transparent 1px);background-size:32px 32px}
.shell{position:relative;max-width:1180px;margin:auto;padding:34px 22px 54px}.top{display:flex;align-items:center;justify-content:space-between;margin-bottom:30px}.brand{display:flex;gap:13px;align-items:center}.mark{width:44px;height:44px;display:grid;place-items:center;border:1px solid #4de2c566;border-radius:13px;background:#4de2c512;box-shadow:0 0 24px #4de2c522;font-size:23px}.brand strong{display:block;font-size:18px;letter-spacing:.08em}.brand small,.muted{color:var(--muted)}.local{padding:8px 12px;border:1px solid var(--line);border-radius:99px;color:var(--cyan);background:#4de2c50a;font-size:12px}.hero{display:grid;grid-template-columns:1.25fr .75fr;gap:20px;margin-bottom:20px}.card{border:1px solid var(--line);border-radius:18px;background:linear-gradient(145deg,#10243aee,#0b1929ee);box-shadow:var(--shadow)}.intro{padding:30px}.eyebrow{color:var(--cyan);text-transform:uppercase;letter-spacing:.16em;font-size:11px;font-weight:800}.intro h1{font-size:clamp(28px,5vw,48px);line-height:1.05;margin:12px 0 14px;max-width:650px}.intro p{color:var(--muted);max-width:630px;font-size:16px}.status{padding:25px;display:flex;flex-direction:column;justify-content:space-between}.status-head{display:flex;align-items:center;gap:10px}.pulse{width:9px;height:9px;border-radius:50%;background:$status_color;box-shadow:0 0 15px $status_color}.status h2{font-size:24px;margin:22px 0 4px}.status p{color:var(--muted);margin:0}.progress{height:6px;background:#06101c;border-radius:10px;overflow:hidden;margin-top:24px}.progress i{display:block;width:$progress;height:100%;background:linear-gradient(90deg,var(--cyan),var(--blue))}.grid{display:grid;grid-template-columns:1.55fr .75fr;gap:20px}.form-card{padding:26px}.section-title{display:flex;align-items:center;gap:12px;margin-bottom:20px}.section-title span{font-size:24px}.section-title h2{font-size:18px;margin:0}.section-title p{font-size:12px;color:var(--muted);margin:2px 0 0}.fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:15px}.field label{display:block;color:#b9cde0;font-size:12px;font-weight:700;margin:0 0 7px}.field input,.field select{width:100%;border:1px solid var(--line);border-radius:10px;background:#071522;color:var(--text);padding:11px 12px;outline:none}.field input:focus,.field select:focus{border-color:var(--cyan);box-shadow:0 0 0 3px #4de2c516}.span2{grid-column:span 2}.scan-row{display:grid;grid-template-columns:1fr auto;gap:9px}.scan-button{border:1px solid #4de2c566;border-radius:10px;background:#4de2c510;color:var(--cyan);padding:0 14px;font-weight:800;cursor:pointer}.scan-button:disabled{opacity:.5;cursor:wait}.scan-hint{display:block;margin-top:6px;color:var(--muted);font-size:11px}.checks{display:flex;gap:12px;align-items:flex-start;border:1px solid #4de2c52e;background:#4de2c508;padding:14px;border-radius:12px;margin:19px 0}.checks input{accent-color:var(--cyan);margin-top:4px}.checks label{font-size:13px;color:#bfd0df}.button{width:100%;border:0;border-radius:11px;padding:13px 16px;background:linear-gradient(100deg,var(--cyan),#77b9ff);color:#03131c;font-weight:900;cursor:pointer}.button:hover{filter:brightness(1.08)}.side{display:grid;gap:20px}.vault,.preview{padding:22px}.vault-list{display:grid;gap:12px;margin-top:16px}.metric{display:flex;justify-content:space-between;padding:12px;border:1px solid var(--line);border-radius:10px;background:#081625}.metric b{color:var(--cyan)}pre{white-space:pre-wrap;word-break:break-word;border:1px solid var(--line);background:#06111d;border-radius:10px;padding:13px;color:#b9d4e9;font-size:11px;min-height:76px}.notice{margin:0 0 18px;padding:12px;border-radius:10px;border:1px solid $notice_border;color:$notice_color;background:$notice_bg}.empty{padding:18px 8px;text-align:center;color:var(--muted)}footer{text-align:center;color:#617c94;font-size:12px;margin-top:24px}@media(max-width:820px){.hero,.grid{grid-template-columns:1fr}.fields{grid-template-columns:1fr}.span2{grid-column:auto}.local{display:none}}
.lock-scene{display:grid;place-items:center;margin:20px 0 2px}.shackle{width:116px;height:54px;border:10px solid #8aa0ae;border-bottom:0;border-radius:58px 58px 0 0;background:transparent;box-shadow:inset 0 0 0 2px #d7e3e8,0 0 24px #4de2c51f}.lock-body{position:relative;padding:11px 13px;border:1px solid #aab8bf;border-radius:10px;background:linear-gradient(145deg,#cbd7dc,#536671 48%,#a9bac2);box-shadow:inset 0 2px 2px #fff8,inset 0 -4px 8px #10192299,0 10px 22px #02070d}.combination{display:flex;gap:4px;padding:5px;border-radius:7px;background:#07111b;box-shadow:inset 0 3px 9px #000}.wheel{position:relative;width:33px;height:42px;overflow:hidden;border:1px solid #263846;border-radius:4px;background:linear-gradient(#07111b,#edf5f8 42%,#fff 50%,#d4e2e8 58%,#07111b);color:#07111b;font:800 21px/42px ui-monospace,monospace;text-align:center}.wheel:after{content:"";position:absolute;inset:0;box-shadow:inset 0 12px 13px #07111baa,inset 0 -12px 13px #07111baa;pointer-events:none}.strip{transform:translateY(calc((36 + var(--symbol,0))*-42px));transition:transform .7s cubic-bezier(.16,.84,.24,1)}.strip span{display:block;height:42px}.combination.spinning .strip{animation:reel 1.1s linear infinite}.lock-caption{margin-top:8px;color:#708ba0;font-size:10px;letter-spacing:.09em;text-transform:uppercase}@keyframes reel{from{transform:translateY(-1512px)}to{transform:translateY(-3024px)}}
@media(min-width:821px){html,body{height:100%;overflow:hidden}.shell{height:100vh;padding:16px 20px 12px}.top{margin-bottom:12px}.hero{gap:12px;margin-bottom:12px}.intro{padding:18px}.intro h1{font-size:32px;margin:7px 0 8px}.intro p{font-size:13px;margin:0}.status{padding:16px}.status h2{font-size:20px;margin:10px 0 2px}.status p{font-size:12px}.lock-scene{margin:8px 0 0;transform:scale(.76);transform-origin:center top;height:144px}.progress{margin-top:3px}.grid{gap:12px}.form-card{padding:16px}.section-title{margin-bottom:10px}.section-title span{font-size:20px}.section-title p{font-size:11px}.fields{gap:8px}.field label{margin-bottom:3px;font-size:11px}.field input,.field select{padding:7px 9px;font-size:13px}.scan-hint{margin-top:2px;font-size:10px}.checks{padding:8px;margin:10px 0}.checks label{font-size:11px}.button{padding:9px}.side{gap:12px}.vault,.preview{padding:14px}.vault-list{gap:7px;margin-top:8px}.metric{padding:8px}.empty{padding:8px;font-size:11px}pre{min-height:55px;padding:8px;margin:8px 0;font-size:10px}footer{margin-top:8px;font-size:10px}}
.launch{margin-top:9px;background:linear-gradient(100deg,#ffca70,#ff8d74)}.launch:disabled{opacity:.55;cursor:not-allowed}
</style></head><body><main class="shell">
<header class="top"><div class="brand"><div class="mark">⬡</div><div><strong>SENTINEL</strong><small>Wi-Fi Security Console</small></div></div><div class="local">● LOCALHOST UNIQUEMENT</div></header>
<section class="hero"><div class="card intro"><div class="eyebrow">Poste de contrôle local</div><h1>Auditez votre hotspot avec précision.</h1><p>Préparez un audit borné, épinglez le BSSID cible et conservez le contrôle. Cette interface génère la commande mais ne lance jamais d’essai radio seule.</p></div>
<div class="card status"><div><div class="status-head"><span class="pulse"></span><span class="eyebrow">État de l’audit</span></div><h2>$status_title</h2><p>$status_text</p><div class="lock-scene" aria-label="Cadran visuel de sécurité"><div><div class="shackle"></div><div class="lock-body"><div class="combination" id="combination"></div></div><div class="lock-caption">Cadran visuel · aucun secret stocké</div></div></div></div><div class="progress"><i></i></div></div></section>
<section class="grid"><div class="card form-card"><div class="section-title"><span>🔑</span><div><h2>Configuration sécurisée</h2><p>Définir une cible unique et une charge bornée</p></div></div>$notice
<form method="post" action="/configure"><div class="fields">
<div class="field span2"><label for="network">Réseaux détectés automatiquement</label><div class="scan-row"><select id="network"><option value="">Recherche au chargement…</option></select><button class="scan-button" id="scan" type="button">↻ Scanner</button></div><small class="scan-hint" id="scan-status">Aucune connexion ne sera tentée pendant le scan.</small></div>
<div class="field span2"><label for="ssid">SSID sélectionné ou saisie manuelle</label><input id="ssid" name="ssid" value="$ssid" placeholder="MonHotspot" required maxlength="64"></div>
<div class="field"><label for="bssid">BSSID à épingler</label><input id="bssid" name="bssid" value="$bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
<div class="field"><label for="interface">Interface Wi-Fi détectée</label><select id="interface" name="interface" required><option value="$interface">$interface</option></select></div>
<div class="field span2"><label for="charset">Jeu de caractères</label><select id="charset" name="charset">$charset_options</select></div>
<div class="field"><label for="min_length">Longueur minimale</label><input id="min_length" name="min_length" type="number" min="1" max="64" value="$min_length"></div>
<div class="field"><label for="max_length">Longueur maximale</label><input id="max_length" name="max_length" type="number" min="1" max="64" value="$max_length"></div>
<div class="field"><label for="limit">Limite d’essais</label><input id="limit" name="limit" type="number" min="1" max="100000" value="$limit"></div>
<div class="field"><label for="timeout">Délai par essai (s)</label><input id="timeout" name="timeout" type="number" min="0.1" max="60" step="0.1" value="$timeout"></div></div>
<div class="checks"><input id="authorized" name="authorized" value="yes" type="checkbox" required><label for="authorized">Je confirme que ce réseau m’appartient ou que je dispose d’une autorisation écrite explicite pour l’auditer.</label></div>
<button class="button" type="submit">Valider la configuration →</button></form><button class="button launch" id="launch" type="button" $start_disabled>$start_label</button></div>
<aside class="side"><section class="card vault"><div class="section-title"><span>🔒</span><div><h2>Coffre-fort</h2><p>Résultats de cette session</p></div></div><div class="vault-list"><div class="metric"><span>Cible verrouillée</span><b>$target_metric</b></div><div class="metric"><span>Limite active</span><b>$limit_metric</b></div><div class="empty">Aucun secret n’est stocké dans l’interface.</div></div></section>
<section class="card preview"><div class="section-title"><span>⌘</span><div><h2>Audit en direct</h2><p>Arrêt automatique à la découverte</p></div></div><pre id="audit-output">$command</pre></section></aside></section>
<footer>Sentinel écoute uniquement sur 127.0.0.1 · aucune télémétrie · aucun stockage persistant</footer></main>
<script>
const network=document.querySelector('#network'),scan=document.querySelector('#scan'),scanStatus=document.querySelector('#scan-status'),iface=document.querySelector('#interface'),ssid=document.querySelector('#ssid'),bssid=document.querySelector('#bssid'),combination=document.querySelector('#combination');
const symbols='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
for(let wheelIndex=0;wheelIndex<6;wheelIndex++){const wheel=document.createElement('div'),strip=document.createElement('div');wheel.className='wheel';strip.className='strip';strip.style.animationDelay=`-$${wheelIndex*.09}s`;for(let symbolIndex=0;symbolIndex<symbols.length*3;symbolIndex++){const symbol=document.createElement('span');symbol.textContent=symbols[symbolIndex%symbols.length];strip.appendChild(symbol)}wheel.appendChild(strip);combination.appendChild(wheel)}
function setCombination(value){String(value).toUpperCase().replace(/[^A-Z0-9]/g,'').padEnd(6,'X').slice(0,6).split('').forEach((symbol,index)=>combination.children[index].querySelector('.strip').style.setProperty('--symbol',symbols.indexOf(symbol)))}
function applyNetwork(){const option=network.options[network.selectedIndex];if(!option||!option.dataset.ssid)return;ssid.value=option.dataset.ssid;bssid.value=option.dataset.bssid;setCombination(option.dataset.ssid)}
async function scanNetworks(){scan.disabled=true;combination.classList.add('spinning');scanStatus.textContent='Scan des réseaux à proximité…';network.innerHTML='<option>Recherche…</option>';try{const response=await fetch('/api/networks?interface='+encodeURIComponent(iface.value));const data=await response.json();if(!response.ok)throw new Error(data.error||'Scan impossible');network.innerHTML='';if(!data.networks.length){network.innerHTML='<option value="">Aucun réseau détecté — saisie manuelle</option>';scanStatus.textContent='Aucun réseau visible. La saisie manuelle reste disponible.';setCombination(0);return}for(const item of data.networks){const option=document.createElement('option');option.dataset.ssid=item.ssid;option.dataset.bssid=item.bssid;option.dataset.signal=item.signal;option.textContent=`$${item.ssid} · $${item.signal}% · $${item.security}`;network.appendChild(option)}applyNetwork();scanStatus.textContent=`$${data.networks.length} point(s) d’accès détecté(s). Le BSSID a été épinglé.`}catch(error){network.innerHTML='<option value="">Scan indisponible — saisie manuelle</option>';scanStatus.textContent=error.message;setCombination(0)}finally{combination.classList.remove('spinning');scan.disabled=false}}
async function initialize(){try{const response=await fetch('/api/interfaces');const data=await response.json();if(data.interfaces&&data.interfaces.length){iface.innerHTML='';for(const item of data.interfaces){const option=document.createElement('option');option.value=item.name;option.textContent=`$${item.name} · $${item.state}`;iface.appendChild(option)}}}catch(_error){}await scanNetworks()}
const launch=document.querySelector('#launch'),auditOutput=document.querySelector('#audit-output');
async function refreshAudit(){try{const response=await fetch('/api/status');const data=await response.json();auditOutput.textContent=data.message;if(data.running){launch.disabled=true;launch.textContent='⟳ Audit en cours…';setTimeout(refreshAudit,1000)}else{launch.disabled=false;launch.textContent=data.found?'✓ Combinaison trouvée':'▶ Lancer l’audit local'}}catch(error){auditOutput.textContent=error.message}}
launch.addEventListener('click',async()=>{launch.disabled=true;launch.textContent='⟳ Démarrage…';const response=await fetch('/api/start',{method:'POST'});const data=await response.json();auditOutput.textContent=data.message;if(response.ok)refreshAudit();else{launch.disabled=false;launch.textContent='▶ Lancer l’audit local'}});
network.addEventListener('change',applyNetwork);scan.addEventListener('click',scanNetworks);iface.addEventListener('change',scanNetworks);window.addEventListener('DOMContentLoaded',()=>{initialize();refreshAudit()});
</script></body></html>""")


def render_page(config=None, message="", error=False):
    config = config or DEFAULTS
    configured = bool(config.get("ssid")) and not error
    options = []
    for value, label in (("digit", "Chiffres"), ("alpha", "Lettres minuscules"),
                         ("alphanumeric", "Alphanumérique"), ("all", "Tous les caractères")):
        selected = " selected" if config.get("charset") == value else ""
        options.append(f'<option value="{value}"{selected}>{label}</option>')
    if message:
        notice = f'<div class="notice">{escape(message)}</div>'
    else:
        notice = ""
    command = build_command(config) if configured else "La commande apparaîtra après validation."
    substitutions = {key: escape(value) for key, value in config.items()}
    substitutions.update({
        "charset_options": "".join(options),
        "notice": notice,
        "notice_border": "#ff738355" if error else "#4de2c555",
        "notice_color": "#ff9eaa" if error else "#8ff3df",
        "notice_bg": "#ff73830d" if error else "#4de2c50d",
        "status_color": "#4de2c5" if configured else "#f6b94f",
        "status_title": "Prêt et verrouillé" if configured else "En attente",
        "status_text": "Configuration prête. La commande reste à lancer manuellement." if configured else "Configurez et autorisez votre cible locale.",
        "progress": "100%" if configured else "12%",
        "target_metric": escape(config["ssid"]) if configured else "Non définie",
        "limit_metric": escape(config["limit"]) if configured else "—",
        "command": escape(command),
        "start_disabled": "" if configured else "disabled",
        "start_label": "▶ Lancer l’audit local" if configured else "🔒 Valider d’abord la configuration",
    })
    return PAGE.safe_substitute(substitutions).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    config = DEFAULTS.copy()
    message = ""
    error = False
    audit_process = None
    audit_message = "Aucun audit lancé."
    audit_found = False

    @classmethod
    def launch_audit(cls):
        if cls.audit_process and cls.audit_process.poll() is None:
            return False, "Un audit est déjà en cours."
        try:
            cls.audit_process = subprocess.Popen(
                build_audit_argv(cls.config), stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, start_new_session=True,
            )
        except OSError as exc:
            cls.audit_process = None
            return False, f"Impossible de lancer l’audit : {exc}"
        cls.audit_found = False
        cls.audit_message = "Audit en cours… arrêt dès que la combinaison est trouvée."
        threading.Thread(target=cls.collect_audit, args=(cls.audit_process,), daemon=True).start()
        return True, cls.audit_message

    @classmethod
    def collect_audit(cls, process):
        stdout, stderr = process.communicate()
        if process.returncode == 0:
            result = stdout.strip().splitlines()[-1] if stdout.strip() else "combinaison trouvée"
            cls.audit_found = True
            cls.audit_message = f"✓ Combinaison trouvée : {result}"
        else:
            detail = stderr.strip().splitlines()[-1] if stderr.strip() else "limite atteinte ou audit interrompu"
            cls.audit_message = f"Audit terminé : {detail}"
        cls.audit_process = None

    def send_page(self, status=200):
        body = render_page(self.config, self.message, self.error)
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/status":
            running = bool(self.__class__.audit_process and self.__class__.audit_process.poll() is None)
            payload = {"running": running, "found": self.__class__.audit_found,
                       "message": self.__class__.audit_message}
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/interfaces":
            try:
                payload = {"interfaces": detect_interfaces()}
                status = 200
            except RuntimeError as exc:
                payload = {"error": str(exc), "interfaces": []}
                status = 400
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/networks":
            interface = parse_qs(parsed.query).get("interface", ["wlan0"])[0]
            try:
                payload = {"networks": detect_networks(interface)}
                status = 200
            except (ValueError, RuntimeError) as exc:
                payload = {"error": str(exc), "networks": []}
                status = 400
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path != "/":
            self.send_error(404)
            return
        self.send_page()

    def do_POST(self):
        if self.path == "/api/start":
            if not self.__class__.config.get("ssid"):
                payload, status = {"message": "Validez d’abord une configuration autorisée."}, 400
            else:
                started, message = self.__class__.launch_audit()
                payload, status = {"message": message}, (202 if started else 409)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/configure":
            self.send_error(404)
            return
        length = min(int(self.headers.get("Content-Length", "0")), 8192)
        parsed = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        values = {key: items[0] for key, items in parsed.items()}
        try:
            self.__class__.config = validate_config(values)
            self.__class__.message = "Configuration enregistrée. La commande est prête ci-dessous ; aucun essai réseau n’a été lancé."
            self.__class__.error = False
            self.__class__.audit_found = False
            self.__class__.audit_message = "Configuration prête. Appuyez sur « Lancer l’audit local »."
            self.send_page()
        except ValueError as exc:
            candidate = DEFAULTS.copy()
            candidate.update({key: values.get(key, candidate[key]) for key in DEFAULTS})
            self.__class__.config = candidate
            self.__class__.message = str(exc)
            self.__class__.error = True
            self.send_page(400)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description="Serve the local Sentinel dashboard.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    address = ("127.0.0.1", args.port)
    url = f"http://{address[0]}:{address[1]}"
    try:
        server = ThreadingHTTPServer(address, Handler)
    except PermissionError:
        print("Erreur: le système interdit l’ouverture du serveur local.", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Erreur: impossible d’écouter sur {url}: {exc}", file=sys.stderr)
        print("Essayez un autre port avec: ./scripts/local_ui.py --port 8766", file=sys.stderr)
        return 1
    print(f"Interface locale: {url}", flush=True)
    if not args.no_browser:
        opener = threading.Timer(0.35, webbrowser.open, args=(url,))
        opener.daemon = True
        opener.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nInterface arrêtée.", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
