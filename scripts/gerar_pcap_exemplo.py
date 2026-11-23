"""Gera um PCAP sintético para testes e demonstração do NetScope.

Contém tráfego "normal" (ARP, ICMP, DNS, HTTP, TLS) e cenários anômalos
controlados: varredura de portas, SYN flood, tunelamento DNS, NXDOMAIN em
excesso e ARP spoofing. Uso:

    python scripts/gerar_pcap_exemplo.py [saida.pcap]
"""
from __future__ import annotations

import random
import string
import struct
import sys

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

random.seed(42)

CLIENT, CLIENT_MAC = "192.168.0.10", "aa:aa:aa:00:00:10"
CLIENT2, CLIENT2_MAC = "192.168.0.11", "aa:aa:aa:00:00:11"
GW, GW_MAC = "192.168.0.1", "aa:aa:aa:00:00:01"
ATTACKER, ATTACKER_MAC = "192.168.0.66", "de:ad:be:ef:00:66"
DNS_SRV = "8.8.8.8"
WEB = "93.184.216.34"
TLS_SRV = "142.250.79.46"

packets = []
T = [1_700_000_000.0]


def emit(pkt, dt=0.001):
    T[0] += dt
    pkt.time = T[0]
    packets.append(pkt)


def eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def tls_client_hello(sni: str) -> bytes:
    sni_b = sni.encode()
    server_name = struct.pack("!BH", 0, len(sni_b)) + sni_b
    sni_ext = struct.pack("!HHH", 0, len(server_name) + 2, len(server_name)) + server_name
    sv_ext = struct.pack("!HHB", 43, 5, 4) + struct.pack("!HH", 0x0304, 0x0303)
    exts = sni_ext + sv_ext
    body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02"
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def tls_server_hello() -> bytes:
    sv_ext = struct.pack("!HHH", 43, 2, 0x0304)
    body = (struct.pack("!H", 0x0303) + bytes(32) + b"\x00" + b"\x13\x01" + b"\x00"
            + struct.pack("!H", len(sv_ext)) + sv_ext)
    hs = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


def tcp_session(cli, cli_mac, srv, sport, dport, req: bytes, resp: bytes, rtt=0.02):
    c2s = lambda: eth(cli_mac, GW_MAC) / IP(src=cli, dst=srv)  # noqa: E731
    s2c = lambda: eth(GW_MAC, cli_mac) / IP(src=srv, dst=cli, ttl=56)  # noqa: E731
    cs, ss = random.randint(1000, 10 ** 9), random.randint(1000, 10 ** 9)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="S", seq=cs), 0.05)
    emit(s2c() / TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=cs + 1), rtt)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1), 0.0005)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="PA", seq=cs + 1, ack=ss + 1) / Raw(req), 0.0005)
    emit(s2c() / TCP(sport=dport, dport=sport, flags="A", seq=ss + 1, ack=cs + 1 + len(req)), rtt)
    emit(s2c() / TCP(sport=dport, dport=sport, flags="PA", seq=ss + 1, ack=cs + 1 + len(req)) / Raw(resp), 0.002)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cs + 1 + len(req), ack=ss + 1 + len(resp)), 0.0005)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="FA", seq=cs + 1 + len(req), ack=ss + 1 + len(resp)), 0.1)
    emit(s2c() / TCP(sport=dport, dport=sport, flags="FA", seq=ss + 1 + len(resp), ack=cs + 2 + len(req)), rtt)
    emit(c2s() / TCP(sport=sport, dport=dport, flags="A", seq=cs + 2 + len(req), ack=ss + 2 + len(resp)), 0.0005)


def dns_query(cli, cli_mac, name, answer_ip=None, qtype="A", rcode=0, rtt=0.015):
    qid = random.randint(0, 0xFFFF)
    sport = random.randint(30000, 60000)
    emit(eth(cli_mac, GW_MAC) / IP(src=cli, dst=DNS_SRV) / UDP(sport=sport, dport=53)
         / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype)), 0.01)
    an = [DNSRR(rrname=name, type="A", ttl=300, rdata=answer_ip)] if answer_ip else []
    emit(eth(GW_MAC, cli_mac) / IP(src=DNS_SRV, dst=cli, ttl=118) / UDP(sport=53, dport=sport)
         / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name, qtype=qtype), an=an), rtt)


def normal_traffic(rounds=3):
    for r in range(rounds):
        emit(eth(CLIENT_MAC, "ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=CLIENT, hwsrc=CLIENT_MAC, pdst=GW), 0.3)
        emit(eth(GW_MAC, CLIENT_MAC) / ARP(op=2, psrc=GW, hwsrc=GW_MAC, pdst=CLIENT, hwdst=CLIENT_MAC), 0.001)
        for seq in range(3):
            emit(eth(CLIENT_MAC, GW_MAC) / IP(src=CLIENT, dst=DNS_SRV) / ICMP(type=8, id=1, seq=seq + r * 3)
                 / Raw(b"abcdefghijklmnopqrstuvwabcdefghi"), 0.2)
            emit(eth(GW_MAC, CLIENT_MAC) / IP(src=DNS_SRV, dst=CLIENT, ttl=118) / ICMP(type=0, id=1, seq=seq + r * 3)
                 / Raw(b"abcdefghijklmnopqrstuvwabcdefghi"), 0.018)
        dns_query(CLIENT, CLIENT_MAC, "example.com", WEB)
        req = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0 (NetScope demo)\r\n"
               b"Accept: */*\r\n\r\n")
        body = b"<html><body><h1>Example Domain</h1></body></html>"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + str(len(body)).encode()
                + b"\r\n\r\n" + body)
        tcp_session(CLIENT, CLIENT_MAC, WEB, 50000 + r, 80, req, resp, rtt=0.03)
        dns_query(CLIENT2, CLIENT2_MAC, "www.google.com", TLS_SRV)
        tcp_session(CLIENT2, CLIENT2_MAC, TLS_SRV, 51000 + r, 443, tls_client_hello("www.google.com"),
                    tls_server_hello(), rtt=0.012)
        dns_query(CLIENT2, CLIENT2_MAC, "ufpb.br", "150.165.254.1")
        tcp_session(CLIENT2, CLIENT2_MAC, "150.165.254.1", 52000 + r, 443, tls_client_hello("ufpb.br"),
                    tls_server_hello(), rtt=0.008)
        emit(Ether() / IP(src=CLIENT, dst=WEB) / TCP(sport=50100 + r, dport=80, flags="R"), 0.5)


def port_scan():
    """nmap -sS: SYN para 200 portas do mesmo alvo em ~2s."""
    target = CLIENT2
    for port in random.sample(range(1, 1025), 200):
        emit(eth(ATTACKER_MAC, CLIENT2_MAC) / IP(src=ATTACKER, dst=target) / TCP(sport=44444, dport=port, flags="S"), 0.01)
        if port in (22, 80, 443):
            emit(eth(CLIENT2_MAC, ATTACKER_MAC) / IP(src=target, dst=ATTACKER) / TCP(sport=port, dport=44444, flags="SA"), 0.0005)
        else:
            emit(eth(CLIENT2_MAC, ATTACKER_MAC) / IP(src=target, dst=ATTACKER) / TCP(sport=port, dport=44444, flags="RA"), 0.0005)


def syn_flood():
    """SYNs de IPs falsificados para a porta 80 de um servidor."""
    for _ in range(400):
        src = f"{random.randint(11, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        emit(Ether(src=ATTACKER_MAC, dst=GW_MAC) / IP(src=src, dst=WEB) / TCP(sport=random.randint(1024, 65535), dport=80, flags="S"), 0.002)


def dns_tunnel():
    """Consultas com subdomínios longos e aleatórios (exfiltração)."""
    for _ in range(60):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
        dns_query(CLIENT, CLIENT_MAC, f"{label}.exfil-data.net", "10.10.10.10", qtype="TXT", rtt=0.02)


def nxdomain_burst():
    for i in range(15):
        name = "".join(random.choices(string.ascii_lowercase, k=random.randint(8, 14))) + ".com"
        dns_query(CLIENT2, CLIENT2_MAC, name, rcode=3)


def arp_spoof():
    for _ in range(5):
        emit(eth(ATTACKER_MAC, CLIENT_MAC) / ARP(op=2, psrc=GW, hwsrc=ATTACKER_MAC, pdst=CLIENT, hwdst=CLIENT_MAC), 0.5)


def main(path="exemplos/exemplo_netscope.pcap"):
    normal_traffic(3)
    port_scan()
    normal_traffic(1)
    syn_flood()
    dns_tunnel()
    nxdomain_burst()
    arp_spoof()
    normal_traffic(2)
    wrpcap(path, packets)
    print(f"{len(packets)} pacotes gravados em {path}")


if __name__ == "__main__":
    main(*sys.argv[1:])
