
# 09 — Ataque DNS Spoofing / DNS Poisoning
DNS Spoofing + servidor web falso integrado


## Objetivo del Laboratorio
Demostrar cómo un atacante puede interceptar consultas DNS y
responder con registros falsificados para redirigir el dominio
itla.edu.do a un servidor web local controlado por el atacante,
permitiendo phishing o captura de credenciales.

---

## Objetivo del Script
Interceptar consultas DNS para dominios específicos y responder
con una IP falsa antes que el servidor DNS legítimo, junto con
un servidor web falso que simula el sitio objetivo.

### Parámetros

| Parámetro | Descripción | Default |
|-----------|-------------|---------|
| `-i` | Interfaz de red | Obligatorio |
| `--target` | Dominio(s) objetivo | itla.edu.do |
| `--redirect` | IP del servidor falso | Obligatorio |
| `--ttl` | TTL de la respuesta falsa | 300 |
| `--web` | Iniciar servidor web falso | False |
| `--web-port` | Puerto del servidor web | 80 |

### Requisitos
- Python 3.8+
- Scapy: `pip3 install scapy`
- Estar en posición MitM (via ARP Spoofing) o misma red
- Ejecutar como root

---

## Topología de Red

```
[Ubuntu-Atacante]──e0/0──[SW-Core]──e0/1──[Linux-Victima]
 192.168.67.50                               192.168.67.60
 (DNS Falso +
  Web Falso)
```

| Dispositivo | Interfaz | IP | Rol |
|---|---|---|---|
| Ubuntu-Atacante | ens3 | 192.168.67.50/24 | DNS + Web falso |
| SW-Core | e0/0 - e0/1 | — | Switch |
| Linux-Victima | ens3 | 192.168.67.60/24 | Objetivo |

---

## Funcionamiento del Script

1. Escucha paquetes UDP en puerto 53 (DNS)
2. Al recibir consulta DNS para `itla.edu.do`:
   - Responde inmediatamente con IP del atacante
   - TTL configurable para controlar duración del cache
3. La víctima recibe la respuesta falsa antes que la legítima
4. El browser de la víctima conecta al servidor web falso
5. El servidor web falso sirve una página que simula itla.edu.do

```
FLUJO NORMAL:
Víctima → DNS Query "itla.edu.do?" → Servidor DNS → Respuesta: 200.10.x.x

FLUJO ATACADO:
Víctima → DNS Query "itla.edu.do?" → ATACANTE responde: 192.168.67.50
Víctima → HTTP GET 192.168.67.50 → Servidor web FALSO del atacante
```

---

## Uso

```bash
# Básico — solo DNS spoofing
sudo python3 dns_spoof.py -i ens3 \
    --target itla.edu.do \
    --redirect 192.168.67.50

# Con servidor web falso integrado
sudo python3 dns_spoof.py -i ens3 \
    --target itla.edu.do \
    --redirect 192.168.67.50 \
    --web

# Múltiples dominios
sudo python3 dns_spoof.py -i ens3 \
    --target "itla.edu.do,google.com" \
    --redirect 192.168.67.50 --web

# Verificar desde la víctima
nslookup itla.edu.do
# Debe responder con 192.168.67.50
```

## Ataque combinado con ARP MitM

```bash
# Terminal 1: ARP MitM para interceptar tráfico
sudo python3 arp_mitm.py -i ens3 -v 192.168.67.60 -g 192.168.67.1

# Terminal 2: DNS Spoofing
sudo python3 dns_spoof.py -i ens3 --target itla.edu.do \
    --redirect 192.168.67.50 --web
```

---

## Capturas de Pantalla

### DNS Spoofing activo
![DNS Spoof](capturas/dns_spoof_activo.png)

### Víctima resolviendo dominio falso
![DNS falso](capturas/dns_spoof_victima.png)

### Página web falsa en el browser
![Web falsa](capturas/dns_spoof_web.png)

---

## Contramedidas

### En el servidor/red
```bash
# DNSSEC — firma criptográfica de registros DNS
# Configurar en el servidor DNS legítimo

# DNS sobre HTTPS (DoH) en los clientes
# Firefox: about:config → network.trr.mode = 2

# Entrada DNS estática en la víctima
echo "200.10.x.x itla.edu.do" >> /etc/hosts
```

### En el switch Cisco
```cisco
! DHCP Snooping + DAI evitan el ARP MitM previo
ip dhcp snooping
ip dhcp snooping vlan 1
ip arp inspection vlan 1
!
! Limitar tráfico DNS (rate limiting)
ip access-list extended BLOCK_DNS_SPOOF
 permit udp any host 8.8.8.8 eq 53
 permit udp any host 1.1.1.1 eq 53
 deny   udp any any eq 53
```

### Verificación
```bash
# Desde la víctima verificar DNS correcto
nslookup itla.edu.do 8.8.8.8
dig itla.edu.do @8.8.8.8
```

---

## Video Demostración
https://youtu.be/iugOXWwREQk

---

## Referencias
- [DNS Spoofing — OWASP](https://owasp.org/www-community/attacks/DNS_Spoofing)
- [DNSSEC Overview](https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en)
- [Scapy DNS Documentation](https://scapy.readthedocs.io)
