"""Validação: compara as contagens do NetScope com as do tshark (Wireshark em linha de comando).

Uso:
    python scripts/comparar_wireshark.py captura.pcap

Requer o tshark instalado (vem junto com o Wireshark).
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from netscope import protocols  # noqa: E402
from netscope.parser import load_pcap  # noqa: E402

def col(df, name):
    """Coluna do DataFrame ou série vazia, se o protocolo não aparece na captura."""
    import pandas as pd
    return df[name] if name in df else pd.Series([None] * len(df), index=df.index)


# (descrição, filtro de exibição do Wireshark, função que conta no NetScope)
CHECKS = [
    ("Total de pacotes", "", lambda df: len(df)),
    ("TCP", "tcp", lambda df: int((df["transport"] == "TCP").sum())),
    ("UDP", "udp", lambda df: int((df["transport"] == "UDP").sum())),
    ("ICMP", "icmp", lambda df: int((df["transport"] == "ICMP").sum())),
    ("ARP", "arp", lambda df: int((df["protocol"] == "ARP").sum())),
    # mDNS e LLMNR usam o formato DNS, mas o Wireshark os exibe como protocolos próprios
    ("DNS", "dns && !mdns && !llmnr", lambda df: int((df["protocol"] == "DNS").sum())),
    ("MDNS", "mdns", lambda df: int((df["protocol"] == "MDNS").sum())),
    ("LLMNR", "llmnr", lambda df: int((df["protocol"] == "LLMNR").sum())),
    ("Consultas DNS", "dns.flags.response == 0 && !mdns && !llmnr", lambda df: int(((df["protocol"] == "DNS") & (col(df, "dns_is_response") == False)).sum())),  # noqa: E712,E501
    ("Requisições HTTP", "http.request", lambda df: int((col(df, "http_type") == "request").sum())),
    ("Respostas HTTP", "http.response", lambda df: int((col(df, "http_type") == "response").sum())),
    ("TLS ClientHello", "tls.handshake.type == 1", lambda df: int((col(df, "tls_handshake") == "ClientHello").sum())),
    ("TLS ServerHello", "tls.handshake.type == 2", lambda df: int((col(df, "tls_handshake") == "ServerHello").sum())),
    ("TCP SYN (sem ACK)", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
     lambda df: int(protocols.tcp_flag_counts(df).set_index("flag").loc["SYN (sem ACK)", "pacotes"])),
    ("TCP RST", "tcp.flags.reset == 1",
     lambda df: int(protocols.tcp_flag_counts(df).set_index("flag").loc["RST", "pacotes"])),
]


def tshark_count(pcap: str, flt: str) -> int:
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-e", "frame.number"]
    if flt:
        cmd += ["-Y", flt]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return len([l for l in out.splitlines() if l.strip()])


def main(pcap: str) -> int:
    if not shutil.which("tshark"):
        print("tshark não encontrado. Instale o Wireshark (inclua o tshark) e tente novamente.")
        return 2
    df = load_pcap(pcap).df
    ok = True
    print(f"{'Métrica':<22}{'NetScope':>10}{'Wireshark':>11}  Resultado")
    print("-" * 56)
    for name, flt, fn in CHECKS:
        mine, ref = fn(df), tshark_count(pcap, flt)
        status = "OK" if mine == ref else "DIFERENTE"
        ok &= mine == ref
        print(f"{name:<22}{mine:>10}{ref:>11}  {status}")
    print("\nObs.: diferenças em HTTP/TLS podem ocorrer quando o Wireshark remonta mensagens divididas em "
          "vários segmentos TCP ou reconhece protocolos em portas não padrão.")
    return 0 if ok else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
