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
    # O gerador faz 6 rodadas de tráfego normal (3 + 1 + 2) reutilizando as portas 50000+r, 51000+r e 52000+r:
    # são 18 conexões distintas (ISNs diferentes), cada uma com 10 pacotes.
    assert len(complete) == 18
    assert set(complete["pacotes"]) == {10}
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


# --------------------------------------------------------------------------- #
# Casos de borda
# --------------------------------------------------------------------------- #
def _load(tmp_path, pkts, t0=1000.0, dt=0.01):
    for i, p in enumerate(pkts):
        if not getattr(p, "_fixed_time", False):
            p.time = t0 + i * dt
    f = tmp_path / "c.pcap"
    wrpcap(str(f), pkts)
    return load_pcap(str(f))


def _syn(src, dst, dport, t, sport=40000):
    p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
    p.time, p._fixed_time = t, True
    return p


def test_episodes_helper():
    # 5 valores distintos em 0,4 s; limiar 5 em janela de 1 s → um único episódio
    assert anomalies.episodes([0.0, 0.1, 0.2, 0.3, 0.4], [1, 2, 3, 4, 5], 1.0, 5) == [(0, 4, 5)]
    # espalhados além da janela → nada
    assert anomalies.episodes([0.0, 2.0, 4.0, 6.0, 8.0], [1, 2, 3, 4, 5], 1.0, 5) == []
    # janelas sobrepostas que disparam viram um episódio só
    assert len(anomalies.episodes([i * 0.1 for i in range(50)], list(range(50)), 1.0, 5)) == 1


def test_port_scan_across_fixed_window_boundary(tmp_path):
    # 30 portas em 1,2 s, começando em t = 9,5 s: metade em [0,10) e metade em [10,20).
    # Janelas fixas de 10 s veriam só 15 portas em cada uma (< 20) e não detectariam.
    pkts = [_syn("1.1.1.1", "1.1.1.2", 1, 1000.0)]  # marca t = 0
    pkts[0][IP].src, pkts[0][IP].dst = "5.5.5.5", "5.5.5.6"
    pkts += [_syn("9.9.9.9", "10.0.0.2", 1000 + i, 1000.0 + 9.5 + i * 0.04) for i in range(30)]
    an = anomalies.detect_all(_load(tmp_path, pkts).df)
    scan = an[an["tipo"] == "Varredura de portas"]
    assert len(scan) == 1
    assert scan.iloc[0]["origem"] == "9.9.9.9" and "30 portas" in scan.iloc[0]["evidencia"]


def test_slow_scan_below_window_not_detected(tmp_path):
    # 30 portas, uma a cada 1 s: nenhuma janela de 10 s chega a 20 portas
    pkts = [_syn("9.9.9.9", "10.0.0.2", 1000 + i, 1000.0 + i) for i in range(30)]
    assert anomalies.detect_all(_load(tmp_path, pkts).df).empty


def test_mdns_llmnr_labeled_and_excluded_from_dns(tmp_path):
    from scapy.layers.llmnr import LLMNRQuery
    pkts = [Ether() / IP(src="10.0.0.5", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
            / DNS(qd=DNSQR(qname="impressora.local")),
            Ether() / IP(src="10.0.0.5", dst="224.0.0.252") / UDP(sport=50000, dport=5355)
            / LLMNRQuery(qd=DNSQR(qname="servidor")),
            Ether() / IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=50001, dport=53)
            / DNS(qd=DNSQR(qname="example.com"))]
    df = _load(tmp_path, pkts).df
    assert list(df["protocol"]) == ["MDNS", "LLMNR", "DNS"]
    assert df.iloc[1]["dns_qname"] == "servidor"
    assert list(protocols.dns_transactions(df)["nome"]) == ["example.com"]


def test_mdns_burst_not_dns_anomaly(tmp_path):
    pkts = [Ether() / IP(src="10.0.0.5", dst="224.0.0.251") / UDP(sport=5353, dport=5353)
            / DNS(qd=DNSQR(qname=f"svc{i}._tcp.local")) for i in range(80)]
    assert anomalies.detect_all(_load(tmp_path, pkts, dt=0.01).df).empty


def _conn(seq, close="F"):
    c, s = ("10.0.0.1", 4000), ("10.0.0.2", 80)
    def pk(src, dst, flags, sq):
        return Ether() / IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags, seq=sq)
    out = [pk(c, s, "S", seq), pk(s, c, "SA", 9000), pk(c, s, "A", seq + 1)]
    if close == "F":
        out += [pk(c, s, "FA", seq + 1), pk(s, c, "FA", 9001), pk(c, s, "A", seq + 2)]
    return out


def test_tcp_port_reuse_splits_sessions(tmp_path):
    sess = protocols.tcp_sessions(_load(tmp_path, _conn(100) + _conn(5000)).df)
    assert len(sess) == 2
    assert list(sess["handshake"]) == ["Completo", "Completo"]
    assert list(sess["encerramento"]) == ["FIN (encerrada)"] * 2
    assert list(sess["pacotes"]) == [6, 6]


def test_tcp_new_isn_without_close_splits(tmp_path):
    # conexão abandonada sem FIN/RST e nova conexão na mesma 4-tupla com outro ISN
    sess = protocols.tcp_sessions(_load(tmp_path, _conn(100, close=None) + _conn(7000)).df)
    assert len(sess) == 2


def test_tcp_syn_retransmission_same_session(tmp_path):
    p = _conn(100)
    pkts = [p[0], p[0].copy()] + p[1:]  # SYN retransmitido (mesmo ISN)
    sess = protocols.tcp_sessions(_load(tmp_path, pkts).df)
    assert len(sess) == 1 and sess.iloc[0]["handshake"] == "Completo" and sess.iloc[0]["pacotes"] == 7


def test_vlan_and_linux_cooked(tmp_path):
    from scapy.all import Dot1Q
    from scapy.layers.l2 import CookedLinux
    df = _load(tmp_path, [Ether() / Dot1Q(vlan=10) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(dport=443, flags="S")]).df
    assert df.iloc[0]["protocol"] == "TCP" and df.iloc[0]["dst_port"] == 443
    f = tmp_path / "sll.pcap"
    wrpcap(str(f), [CookedLinux() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(flags="S")])
    cap = load_pcap(str(f))
    assert cap.df.iloc[0]["src_ip"] == "1.1.1.1"
    assert [l["name"] for l in packet_view.layers(rebuild_packet(cap, 0))][1:] == ["IP", "TCP"]


def test_tls_servers_with_port_reuse(cap):
    # O exemplo reutiliza portas entre rodadas: cada ClientHello deve contar uma única conexão
    srv = protocols.tls_servers(cap.df).set_index("sni")
    hs = protocols.tls_handshakes(cap.df)
    ch = hs[hs["tls_handshake"] == "ClientHello"]["tls_sni"].value_counts()
    assert srv["conexoes"].to_dict() == ch.to_dict() == {"www.google.com": 6, "ufpb.br": 6}
