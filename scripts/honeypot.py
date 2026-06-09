#!/usr/bin/env python3
"""
ViaDigiTech SOC — Honeypot SSH (port 2222)
Toute connexion est par définition malveillante → log + ban immédiat.
Lance un serveur TCP qui envoie un faux banner SSH, logue l'IP, la banne.
"""
import os
import re
import socket
import subprocess
import threading
import time
import json
import requests
from datetime import datetime

HONEYPOT_PORT = 2222
HONEYPOT_BANNER = b"SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6\r\n"
AUDIT_LOG   = "/home/ubuntu/secops/audit_actions.csv"
DEDUP_FILE  = "/tmp/honeypot_seen.json"
DEDUP_TTL   = 3600  # ban une seule fois par heure par IP
TELEGRAM_TOKEN   = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def load_dedup():
    try:
        if os.path.exists(DEDUP_FILE):
            with open(DEDUP_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_dedup(data):
    try:
        with open(DEDUP_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def already_seen(ip):
    data = load_dedup()
    ts = data.get(ip, 0)
    return (time.time() - ts) < DEDUP_TTL


def mark_seen(ip):
    data = load_dedup()
    # Purge old entries
    now = time.time()
    data = {k: v for k, v in data.items() if now - v < DEDUP_TTL}
    data[ip] = now
    save_dedup(data)


def write_audit(ip, note=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts},{ip},HONEYPOT_HIT,100,{note}\n"
    with open(AUDIT_LOG, "a") as f:
        f.write(line)


def ban_ip(ip):
    try:
        r = subprocess.run(
            ["sudo", "fail2ban-client", "set", "sshd", "banip", ip],
            capture_output=True, text=True, timeout=10
        )
        return r.returncode == 0
    except Exception:
        return False


def send_telegram(msg):
    cfg_file = "/home/ubuntu/secops/soc_config.json"
    token, chat_id = TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
    if not token or not chat_id:
        try:
            with open(cfg_file) as f:
                cfg = json.load(f)
            token   = cfg.get("telegram_token", token)
            chat_id = cfg.get("telegram_chat_id", chat_id)
        except Exception:
            pass
    if not token or not chat_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": msg, "parse_mode": "HTML"},
            timeout=5
        )
    except Exception:
        pass


def handle_connection(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(3)
        conn.send(HONEYPOT_BANNER)
        try:
            conn.recv(256)  # lire le banner client
        except Exception:
            pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

    if not IP_RE.match(ip):
        return
    if already_seen(ip):
        print(f"[Honeypot] {ip} — déjà banni (TTL)")
        return

    mark_seen(ip)
    banned = ban_ip(ip)
    write_audit(ip, "connexion honeypot port 2222")

    ts = datetime.now().strftime("%H:%M:%S")
    status = "banni" if banned else "log seulement (ban échoué)"
    print(f"[Honeypot] [{ts}] {ip} → {status}")

    hostname = os.uname().nodename
    send_telegram(
        f"🍯 <b>HONEYPOT HIT</b>\n"
        f"IP: <code>{ip}</code>\n"
        f"Port: 2222\n"
        f"Action: {'✅ Banni via Fail2Ban' if banned else '⚠ Log seulement'}\n"
        f"Serveur: {hostname}"
    )


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", HONEYPOT_PORT))
    sock.listen(50)
    print(f"[Honeypot] Écoute sur port {HONEYPOT_PORT}...")

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_connection, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[Honeypot] Erreur accept: {e}")
            time.sleep(1)

    sock.close()


if __name__ == "__main__":
    main()
