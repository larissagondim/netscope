"""Testes automatizados (pytest) com o PCAP sintético de exemplo."""
from pathlib import Path

import pytest
from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

from netscope import anomalies, packet_view, protocols, stats
from netscope.parser import load_pcap, parse_http, parse_tls, rebuild_packet

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def cap(tmp_path_factory):
    from scripts.gerar_pcap_exemplo import main
    path = tmp_path_factory.mktemp("pcap") / "exemplo.pcap"
    main(str(path))
    return load_pcap(str(path))


def test_counts(cap):
    df = cap.df
    assert len(df) == 1225
    dist = stats.protocol_distribution(df).set_index("protocolo")["pacotes"]
    assert dist["DNS"] == 186 and dist["HTTP"] == 12 and dist["TLS"] == 24 and dist["ARP"] == 17
    assert dist.sum() == len(df)


def test_dns(cap):
    tx = protocols.dns_transactions(cap.df)
    s = protocols.dns_summary(tx)
    assert s["consultas"] == 93 and s["sem_resposta"] == 0 and s["nxdomain"] == 15


def test_tcp_handshake(cap):
    sess = protocols.tcp_sessions(cap.df)
    complete = sess[sess["handshake"] == "Completo"]
    assert len(complete) == 9
    assert set(complete["rtt_handshake_ms"].round()) == {30.0, 12.0, 8.0}


def test_http_tls(cap):
    http = protocols.http_messages(cap.df)
    assert (http["http_method"] == "GET").sum() == 6
    srv = protocols.tls_servers(cap.df)
    assert set(srv["sni"]) == {"www.google.com", "ufpb.br"}
    assert set(srv["versao_negociada"]) == {"TLS 1.3"}


def test_anomalies(cap):
    an = anomalies.detect_all(cap.df)
    types = set(an["tipo"])
    assert "Varredura de portas" in types
    assert "Excesso de SYN (possível SYN flood)" in types
    assert "Conflito ARP (possível ARP spoofing)" in types
    assert "Nomes DNS incomuns (longos / alta entropia)" in types
    assert "Muitas respostas NXDOMAIN" in types
    # A varredura não deve ser contada duas vezes como SYN flood
    assert (an["tipo"] == "Excesso de SYN (possível SYN flood)").sum() == 1


def test_no_false_positive_on_normal_traffic(tmp_path):
    pk = []
    for i in range(30):
        p = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=40000 + i, dport=53) / DNS(qd=DNSQR(qname="example.com"))
        p.time = 1000 + i
        pk.append(p)
    f = tmp_path / "n.pcap"
    wrpcap(str(f), pk)
    assert anomalies.detect_all(load_pcap(str(f)).df).empty


def test_layers(cap):
    idx = int(cap.df[cap.df["protocol"] == "HTTP"]["no"].iloc[0]) - 1
    lys = packet_view.layers(rebuild_packet(cap, idx))
    assert [l["name"] for l in lys] == ["Ethernet", "IP", "TCP", "Raw"]
    assert [l["header_len"] for l in lys[:3]] == [14, 20, 20]
    assert lys[3]["offset"] == 54


def test_parsers():
    assert parse_http(b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n")["http_host"] == "x"
    assert parse_http(b"HTTP/1.1 404 Not Found\r\n\r\n")["http_status"] == "404"
    assert parse_http(b"\x16\x03\x01") is None
    assert parse_tls(b"\x17\x03\x03\x00\x10")["tls_content_type"] == "ApplicationData"
    assert parse_tls(b"GET / HTTP/1.1") is None
