"""Leitura de arquivos PCAP/PCAPNG e extração dos campos de cada pacote.

O resultado principal é um ``pandas.DataFrame`` com uma linha por pacote,
mais a lista de bytes brutos de cada quadro (usada depois para a inspeção
camada a camada, sem precisar manter todos os objetos Scapy em memória).
"""
from __future__ import annotations

import io
from dataclasses import dataclass, field

import pandas as pd
from scapy.all import (
    ARP,
    DNS,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    IPv6,
    PcapReader,
)
from scapy.layers.inet6 import _ICMPv6
from scapy.layers.llmnr import LLMNRQuery, LLMNRResponse
import scapy.all as scapy_all

# Tipos de registro DNS mais comuns (para exibir nome em vez de número)
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

TLS_VERSIONS = {
    0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
    0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}
TLS_CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
TLS_HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 11: "Certificate", 16: "ClientKeyExchange"}

# DNS "irmãos" que usam o mesmo formato de mensagem, mas são protocolos distintos
# (o Wireshark os exibe como MDNS e LLMNR). Ficam fora das análises/anomalias de DNS.
DNS_LIKE_PORTS = {5353: "MDNS", 5355: "LLMNR"}

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")

TCP_FLAG_NAMES = [("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"), ("U", "URG"), ("E", "ECE"), ("C", "CWR")]


@dataclass
class Capture:
    """Resultado da leitura de uma captura."""

    df: pd.DataFrame
    raw: list[bytes] = field(default_factory=list)
    link_cls: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Auxiliares de protocolos de aplicação
# --------------------------------------------------------------------------- #
def parse_http(payload: bytes) -> dict | None:
    """Reconhece a primeira linha e cabeçalhos de uma mensagem HTTP/1.x."""
    if not payload:
        return None
    is_req = payload.startswith(HTTP_METHODS)
    is_resp = payload.startswith(b"HTTP/1.")
    if not (is_req or is_resp):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="replace")
    lines = head.split("\r\n")
    first = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    out = {"http_type": "request" if is_req else "response", "http_host": headers.get("host"),
           "http_user_agent": headers.get("user-agent"), "http_content_type": headers.get("content-type")}
    parts = first.split(" ")
    if is_req and len(parts) >= 2:
        out["http_method"], out["http_uri"] = parts[0], parts[1]
    elif is_resp and len(parts) >= 2:
        out["http_status"] = parts[1]
        out["http_reason"] = " ".join(parts[2:])
    return out


def parse_tls(payload: bytes) -> dict | None:
    """Interpreta o cabeçalho de registro TLS e, se houver, o ClientHello/ServerHello.

    Feito manualmente (sem a camada TLS do Scapy) para ser rápido e tolerante a
    capturas truncadas. Extrai: tipo de conteúdo, versão, tipo de handshake e SNI.
    """
    if len(payload) < 5 or payload[0] not in TLS_CONTENT_TYPES or payload[1] != 0x03 or payload[2] > 0x04:
        return None
    out = {
        "tls_content_type": TLS_CONTENT_TYPES[payload[0]],
        "tls_record_version": TLS_VERSIONS.get(int.from_bytes(payload[1:3], "big"), hex(int.from_bytes(payload[1:3], "big"))),
    }
    if payload[0] != 22 or len(payload) < 6:
        return out
    hs_type = payload[5]
    out["tls_handshake"] = TLS_HANDSHAKE_TYPES.get(hs_type, f"type {hs_type}")
    if hs_type not in (1, 2):
        return out
    try:
        p = 9  # 5 (registro) + 1 (tipo) + 3 (tamanho)
        out["tls_version"] = TLS_VERSIONS.get(int.from_bytes(payload[p:p + 2], "big"))
        p += 2 + 32  # versão + random
        sid_len = payload[p]
        p += 1 + sid_len
        if hs_type == 1:
            cs_len = int.from_bytes(payload[p:p + 2], "big")
            p += 2 + cs_len
            comp_len = payload[p]
            p += 1 + comp_len
        else:
            p += 2 + 1  # cipher suite escolhida + compressão
        ext_total = int.from_bytes(payload[p:p + 2], "big")
        p += 2
        end = min(p + ext_total, len(payload))
        while p + 4 <= end:
            ext_type = int.from_bytes(payload[p:p + 2], "big")
            ext_len = int.from_bytes(payload[p + 2:p + 4], "big")
            data = payload[p + 4:p + 4 + ext_len]
            if ext_type == 0 and hs_type == 1 and len(data) >= 5:  # server_name
                name_len = int.from_bytes(data[3:5], "big")
                out["tls_sni"] = data[5:5 + name_len].decode("ascii", errors="replace")
            elif ext_type == 43:  # supported_versions (indica TLS 1.3)
                if hs_type == 2 and len(data) >= 2:
                    out["tls_version"] = TLS_VERSIONS.get(int.from_bytes(data[:2], "big"), out.get("tls_version"))
                elif hs_type == 1 and len(data) >= 3:
                    versions = [int.from_bytes(data[i:i + 2], "big") for i in range(1, 1 + data[0], 2)]
                    known = [v for v in versions if v in TLS_VERSIONS]
                    if known:
                        out["tls_version"] = TLS_VERSIONS[max(known)]
            p += 4 + ext_len
    except (IndexError, ValueError):
        pass
    return out


def tcp_flags_str(flags) -> str:
    s = str(flags)
    return ",".join(name for letter, name in TCP_FLAG_NAMES if letter in s)


# --------------------------------------------------------------------------- #
# Extração de um pacote
# --------------------------------------------------------------------------- #
def extract(pkt, number: int) -> dict:
    """Converte um pacote Scapy em um dicionário plano de campos."""
    rec: dict = {
        "no": number,
        "time": float(pkt.time),
        "length": len(pkt),
        "src_mac": None, "dst_mac": None,
        "src_ip": None, "dst_ip": None, "ip_version": None, "ttl": None,
        "transport": None, "src_port": None, "dst_port": None,
        "tcp_flags": None, "tcp_seq": None, "tcp_ack": None, "tcp_window": None,
        "payload_len": 0,
        "protocol": "Outro",
        "info": pkt.summary(),
    }
    if Ether in pkt:
        rec["src_mac"], rec["dst_mac"] = pkt[Ether].src, pkt[Ether].dst

    if ARP in pkt:
        a = pkt[ARP]
        rec.update(protocol="ARP", src_ip=a.psrc, dst_ip=a.pdst, arp_op="request" if a.op == 1 else "reply",
                   arp_hwsrc=a.hwsrc)
        rec["info"] = (f"Who has {a.pdst}? Tell {a.psrc}" if a.op == 1 else f"{a.psrc} is at {a.hwsrc}")
        return rec

    if IP in pkt:
        ip = pkt[IP]
        rec.update(src_ip=ip.src, dst_ip=ip.dst, ip_version=4, ttl=ip.ttl, protocol="IPv4")
    elif IPv6 in pkt:
        ip = pkt[IPv6]
        rec.update(src_ip=ip.src, dst_ip=ip.dst, ip_version=6, ttl=ip.hlim, protocol="IPv6")
    else:
        rec["protocol"] = pkt.lastlayer().name if pkt.lastlayer() is not None else "Outro"
        return rec

    payload = b""
    if TCP in pkt:
        t = pkt[TCP]
        payload = bytes(t.payload)
        rec.update(transport="TCP", protocol="TCP", src_port=t.sport, dst_port=t.dport,
                   tcp_flags=tcp_flags_str(t.flags), tcp_seq=t.seq, tcp_ack=t.ack, tcp_window=t.window)
        rec["info"] = f"{t.sport} → {t.dport} [{rec['tcp_flags']}] Seq={t.seq} Ack={t.ack} Win={t.window} Len={len(payload)}"
    elif UDP in pkt:
        u = pkt[UDP]
        payload = bytes(u.payload)
        rec.update(transport="UDP", protocol="UDP", src_port=u.sport, dst_port=u.dport)
        rec["info"] = f"{u.sport} → {u.dport} Len={len(payload)}"
    elif ICMP in pkt:
        ic = pkt[ICMP]
        rec.update(transport="ICMP", protocol="ICMP", icmp_type=ic.type, icmp_code=ic.code)
        names = {0: "Echo reply", 8: "Echo request", 3: "Destination unreachable", 11: "Time exceeded"}
        rec["info"] = f"{names.get(ic.type, 'type ' + str(ic.type))} (code {ic.code})"
    elif pkt.haslayer(_ICMPv6):
        ic = pkt.getlayer(_ICMPv6)
        rec.update(transport="ICMPv6", protocol="ICMPv6", icmp_type=ic.type, icmp_code=getattr(ic, "code", None))
        rec["info"] = ic.name
    rec["payload_len"] = len(payload)

    # ---- Camada de aplicação ----
    d = next((pkt.getlayer(c) for c in (DNS, LLMNRQuery, LLMNRResponse) if pkt.haslayer(c)), None)
    if d is not None:
        label = "DNS"
        for port in (rec["src_port"], rec["dst_port"]):
            if port in DNS_LIKE_PORTS:
                label = DNS_LIKE_PORTS[port]
                break
        rec["protocol"] = label
        rec["dns_id"] = d.id
        rec["dns_is_response"] = bool(d.qr)
        rec["dns_rcode"] = DNS_RCODES.get(d.rcode, str(d.rcode))
        if d.qd is not None and d.qdcount:
            q = d.qd[0] if hasattr(d.qd, "__getitem__") else d.qd
            rec["dns_qname"] = q.qname.decode(errors="replace").rstrip(".") if isinstance(q.qname, bytes) else str(q.qname).rstrip(".")
            rec["dns_qtype"] = DNS_QTYPES.get(q.qtype, str(q.qtype))
        answers = []
        if d.qr and d.ancount and d.an is not None:
            for rr in d.an:
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="replace")
                elif isinstance(rdata, list):
                    rdata = " ".join(x.decode(errors="replace") if isinstance(x, bytes) else str(x) for x in rdata)
                answers.append(str(rdata).rstrip("."))
        rec["dns_answers"] = ", ".join(answers) if answers else None
        kind = "resposta" if d.qr else "consulta"
        rec["info"] = f"{label} {kind} 0x{d.id:04x} {rec.get('dns_qtype', '')} {rec.get('dns_qname', '')}" + (
            f" → {rec['dns_answers']}" if answers else (f" [{rec['dns_rcode']}]" if d.qr else ""))
        return rec

    if rec["transport"] == "TCP" and payload:
        http = parse_http(payload)
        if http:
            rec.update(http)
            rec["protocol"] = "HTTP"
            first_line = payload.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            rec["info"] = first_line
            return rec
        tls = parse_tls(payload)
        if tls:
            rec.update(tls)
            rec["protocol"] = "TLS"
            desc = tls.get("tls_handshake") or tls["tls_content_type"]
            rec["info"] = f"{tls.get('tls_version') or tls['tls_record_version']} {desc}" + (
                f" (SNI: {tls['tls_sni']})" if tls.get("tls_sni") else "")
            return rec
    return rec


# --------------------------------------------------------------------------- #
# API pública
# --------------------------------------------------------------------------- #
def load_pcap(source, max_packets: int | None = None) -> Capture:
    """Lê um arquivo PCAP/PCAPNG (caminho, bytes ou objeto de arquivo)."""
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)
    records, raw, link_cls = [], [], []
    with PcapReader(source) as reader:
        for i, pkt in enumerate(reader, start=1):
            if max_packets and i > max_packets:
                break
            try:
                records.append(extract(pkt, i))
            except Exception as exc:  # pacote malformado não deve derrubar a análise
                records.append({"no": i, "time": float(pkt.time), "length": len(pkt),
                                "protocol": "Malformado", "info": f"Erro ao interpretar: {exc}"})
            raw.append(bytes(pkt))
            link_cls.append(type(pkt).__name__)
    return Capture(df=to_dataframe(records), raw=raw, link_cls=link_cls)


def load_packets(packets) -> Capture:
    """Mesmo que ``load_pcap``, mas a partir de uma lista de pacotes já em memória (captura ao vivo)."""
    records = [extract(p, i) for i, p in enumerate(packets, start=1)]
    return Capture(df=to_dataframe(records), raw=[bytes(p) for p in packets],
                   link_cls=[type(p).__name__ for p in packets])


def to_dataframe(records: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame.from_records(records)
    if df.empty:
        return df
    t0 = df["time"].min()
    df["rel_time"] = df["time"] - t0
    df["timestamp"] = pd.to_datetime(df["time"], unit="s")
    for col in ("src_port", "dst_port", "ip_version", "ttl"):
        if col in df:
            df[col] = df[col].astype("Int64")
    return df


def rebuild_packet(capture: Capture, index: int):
    """Reconstrói o objeto Scapy do pacote de índice ``index`` (0-based)."""
    cls = getattr(scapy_all, capture.link_cls[index], Ether)
    pkt = cls(capture.raw[index])
    pkt.time = capture.df.iloc[index]["time"]
    return pkt
