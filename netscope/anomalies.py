"""Identificação de comportamentos potencialmente anômalos por regras (heurísticas).

Cada regra gera *indícios*, não confirmações de ataque. Todos os limiares são
configuráveis pela interface (``Thresholds``).
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass

import pandas as pd


@dataclass
class Thresholds:
    window_s: float = 10.0            # janela de tempo para contagens
    scan_ports: int = 20              # portas distintas de um mesmo destino por origem na janela
    scan_hosts: int = 15              # hosts distintos (mesma porta) por origem na janela (varredura horizontal)
    syn_count: int = 100              # SYNs sem ACK para um mesmo destino na janela
    syn_ratio: float = 3.0            # razão SYN / SYN-ACK considerada suspeita
    dns_rate: int = 50                # consultas DNS por origem na janela
    dns_name_len: int = 50            # comprimento de nome de domínio considerado longo
    dns_entropy: float = 3.8          # entropia do subdomínio mais à esquerda (bits/char)
    dns_nxdomain: int = 10            # respostas NXDOMAIN para um mesmo cliente
    icmp_rate: int = 100              # pacotes ICMP de uma origem na janela

    def as_dict(self):
        return asdict(self)


COLUMNS = ["severidade", "tipo", "origem", "alvo", "inicio_s", "fim_s", "evidencia", "descricao"]


def _window(df: pd.DataFrame, w: float) -> pd.Series:
    return (df["rel_time"] // w) * w


def _flagset(s):
    return set(s.split(",")) if isinstance(s, str) and s else set()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# --------------------------------------------------------------------------- #
# Regras
# --------------------------------------------------------------------------- #
def detect_port_scan(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    """Muitas portas distintas acessadas por uma origem em curto intervalo."""
    out = []
    d = df[df["transport"].isin(["TCP", "UDP"])].copy()
    if d.empty:
        return out
    # Para TCP considera apenas tentativas de conexão (SYN sem ACK); para UDP, qualquer datagrama
    is_syn = d["tcp_flags"].map(lambda s: "SYN" in _flagset(s) and "ACK" not in _flagset(s))
    d = d[(d["transport"] == "UDP") | is_syn]
    d = d[~d["protocol"].isin(["DNS"])]
    if d.empty:
        return out
    d["w"] = _window(d, th.window_s)

    # Varredura vertical: muitas portas em um mesmo host
    g = d.groupby(["src_ip", "dst_ip", "w"]).agg(
        portas=("dst_port", "nunique"), pacotes=("no", "count"), ini=("rel_time", "min"), fim=("rel_time", "max"),
        amostra=("dst_port", lambda s: ", ".join(map(str, sorted(set(s))[:10]))))
    for (src, dst, w), r in g[g["portas"] >= th.scan_ports].iterrows():
        out.append({
            "severidade": "Alta" if r.portas >= 3 * th.scan_ports else "Média",
            "tipo": "Varredura de portas",
            "origem": src, "alvo": dst, "inicio_s": r.ini, "fim_s": r.fim,
            "evidencia": f"{int(r.portas)} portas distintas em {r.fim - r.ini:.2f}s ({int(r.pacotes)} pacotes). Ex.: {r.amostra}…",
            "descricao": "Uma única origem tentou contato com muitas portas do mesmo destino em pouco tempo, "
                         "padrão típico de ferramentas de varredura (ex.: nmap -sS).",
        })

    # Varredura horizontal: mesma porta em muitos hosts
    g2 = d.groupby(["src_ip", "dst_port", "w"]).agg(
        hosts=("dst_ip", "nunique"), ini=("rel_time", "min"), fim=("rel_time", "max"))
    for (src, port, w), r in g2[g2["hosts"] >= th.scan_hosts].iterrows():
        out.append({
            "severidade": "Média", "tipo": "Varredura de hosts",
            "origem": src, "alvo": f"porta {port}", "inicio_s": r.ini, "fim_s": r.fim,
            "evidencia": f"{int(r.hosts)} hosts distintos contatados na porta {port} em {r.fim - r.ini:.2f}s",
            "descricao": "Uma origem tentou acessar o mesmo serviço em muitos hosts (varredura horizontal).",
        })
    return out


def detect_syn_flood(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    """Quantidade elevada de SYN sem a correspondente resposta/conclusão do handshake."""
    out = []
    t = df[df["transport"] == "TCP"].copy()
    if t.empty:
        return out
    fl = t["tcp_flags"].map(_flagset)
    t["syn"] = fl.map(lambda f: "SYN" in f and "ACK" not in f)
    t["synack"] = fl.map(lambda f: {"SYN", "ACK"} <= f)
    t["w"] = _window(t, th.window_s)
    syn = t[t["syn"]].groupby(["dst_ip", "w"]).agg(
        syns=("no", "count"), origens=("src_ip", "nunique"), portas_dest=("dst_port", "nunique"),
        ini=("rel_time", lambda s: s.quantile(0.05)), fim=("rel_time", lambda s: s.quantile(0.95)))
    synack = t[t["synack"]].groupby(["src_ip", "w"]).size()
    for (dst, w), r in syn.iterrows():
        sa = int(synack.get((dst, w), 0))
        syns, origens = int(r.syns), int(r.origens)
        ratio = syns / max(sa, 1)
        # Origem única tocando muitas portas = varredura (já reportada por detect_port_scan)
        if origens == 1 and int(r.portas_dest) >= th.scan_ports:
            continue
        if syns >= th.syn_count and ratio >= th.syn_ratio:
            spoof = origens > 0.5 * syns
            out.append({
                "severidade": "Alta",
                "tipo": "Excesso de SYN (possível SYN flood)",
                "origem": f"{origens} origens distintas" if origens > 1 else
                          t[(t["syn"]) & (t["dst_ip"] == dst) & (t["w"] == w)]["src_ip"].iloc[0],
                "alvo": dst, "inicio_s": r.ini, "fim_s": r.fim,
                "evidencia": f"{syns} SYN vs {sa} SYN-ACK (razão {ratio:.1f}) na janela de {th.window_s:g}s"
                             + ("; muitas origens distintas (possível IP falsificado)" if spoof else ""),
                "descricao": "Grande volume de pedidos de conexão sem conclusão do three-way handshake, "
                             "o que pode esgotar a fila de conexões semiabertas do servidor.",
            })
    return out


def detect_dns_anomalies(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    out = []
    d = df[(df["protocol"] == "DNS")].copy()
    if d.empty or "dns_is_response" not in d:
        return out
    q = d[d["dns_is_response"] == False].copy()  # noqa: E712
    if not q.empty:
        # 1) Taxa elevada de consultas
        q["w"] = _window(q, th.window_s)
        g = q.groupby(["src_ip", "w"]).agg(n=("no", "count"), dominios=("dns_qname", "nunique"),
                                            ini=("rel_time", lambda s: s.quantile(0.05)),
                                            fim=("rel_time", lambda s: s.quantile(0.95)))
        for (src, w), r in g[g["n"] >= th.dns_rate].iterrows():
            out.append({
                "severidade": "Média", "tipo": "Volume elevado de consultas DNS",
                "origem": src, "alvo": "servidores DNS", "inicio_s": r.ini, "fim_s": r.fim,
                "evidencia": f"{int(r.n)} consultas ({int(r.dominios)} nomes distintos) na janela de {th.window_s:g}s",
                "descricao": "Taxa de consultas muito acima do normal para um host; pode indicar malware, "
                             "tunelamento DNS ou mau funcionamento.",
            })
        # 2) Nomes longos / alta entropia (indícios de tunelamento ou DGA)
        q["nome"] = q["dns_qname"].fillna("")
        q["sub"] = q["nome"].map(lambda n: n.split(".")[0] if n else "")
        q["ent"] = q["sub"].map(entropy)
        sus = q[(q["nome"].str.len() >= th.dns_name_len) | ((q["sub"].str.len() >= 12) & (q["ent"] >= th.dns_entropy))]
        for src, grp in sus.groupby("src_ip"):
            base = grp["nome"].map(lambda n: ".".join(n.split(".")[-2:])).value_counts()
            out.append({
                "severidade": "Média" if len(grp) >= 5 else "Baixa",
                "tipo": "Nomes DNS incomuns (longos / alta entropia)",
                "origem": src, "alvo": ", ".join(base.index[:3]),
                "inicio_s": grp["rel_time"].min(), "fim_s": grp["rel_time"].max(),
                "evidencia": f"{len(grp)} consultas suspeitas; ex.: {grp['nome'].iloc[0][:80]} "
                             f"(len={len(grp['nome'].iloc[0])}, entropia={grp['ent'].iloc[0]:.2f})",
                "descricao": "Subdomínios longos e aleatórios são característicos de tunelamento DNS "
                             "(exfiltração de dados) ou de domínios gerados por algoritmo (DGA).",
            })
    # 3) Muitas respostas NXDOMAIN
    r = d[(d["dns_is_response"] == True) & (d.get("dns_rcode") == "NXDOMAIN")]  # noqa: E712
    for cli, grp in r.groupby("dst_ip"):
        if len(grp) >= th.dns_nxdomain:
            out.append({
                "severidade": "Baixa", "tipo": "Muitas respostas NXDOMAIN",
                "origem": cli, "alvo": "servidores DNS",
                "inicio_s": grp["rel_time"].min(), "fim_s": grp["rel_time"].max(),
                "evidencia": f"{len(grp)} consultas para domínios inexistentes",
                "descricao": "Consultas repetidas a domínios inexistentes podem indicar DGA, má configuração "
                             "ou enumeração de subdomínios.",
            })
    return out


def detect_arp_spoofing(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    """Um mesmo IP anunciado por mais de um endereço MAC em respostas ARP."""
    out = []
    if "arp_op" not in df:
        return out
    a = df[(df["protocol"] == "ARP") & (df["arp_op"] == "reply")]
    for ip, grp in a.groupby("src_ip"):
        macs = grp["arp_hwsrc"].dropna().unique()
        if len(macs) > 1:
            # período do conflito: respostas vindas de MACs diferentes do primeiro anunciado
            conflict = grp[grp["arp_hwsrc"] != macs[0]]
            out.append({
                "severidade": "Alta", "tipo": "Conflito ARP (possível ARP spoofing)",
                "origem": ", ".join(macs), "alvo": ip,
                "inicio_s": conflict["rel_time"].min(), "fim_s": conflict["rel_time"].max(),
                "evidencia": f"IP {ip} anunciado por {len(macs)} MACs distintos em {len(grp)} respostas ARP",
                "descricao": "Diferentes interfaces afirmam possuir o mesmo IP. Pode indicar envenenamento "
                             "de cache ARP (ataque man-in-the-middle) ou conflito de endereçamento.",
            })
    return out


def detect_icmp_flood(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    out = []
    i = df[df["transport"] == "ICMP"].copy()
    if i.empty:
        return out
    i["w"] = _window(i, th.window_s)
    g = i.groupby(["src_ip", "dst_ip", "w"]).agg(n=("no", "count"), ini=("rel_time", "min"), fim=("rel_time", "max"))
    for (src, dst, w), r in g[g["n"] >= th.icmp_rate].iterrows():
        out.append({
            "severidade": "Média", "tipo": "Volume elevado de ICMP",
            "origem": src, "alvo": dst, "inicio_s": r.ini, "fim_s": r.fim,
            "evidencia": f"{int(r.n)} pacotes ICMP em {r.fim - r.ini:.2f}s",
            "descricao": "Taxa elevada de mensagens ICMP (ex.: ping flood) ou varredura por ICMP.",
        })
    return out


RULES = [detect_port_scan, detect_syn_flood, detect_dns_anomalies, detect_arp_spoofing, detect_icmp_flood]


def detect_all(df: pd.DataFrame, th: Thresholds | None = None) -> pd.DataFrame:
    th = th or Thresholds()
    if df.empty:
        return pd.DataFrame(columns=COLUMNS)
    found = []
    for rule in RULES:
        found.extend(rule(df, th))
    res = pd.DataFrame(found, columns=COLUMNS)
    if res.empty:
        return res
    order = {"Alta": 0, "Média": 1, "Baixa": 2}
    res["inicio_s"] = res["inicio_s"].astype(float).round(3)
    res["fim_s"] = res["fim_s"].astype(float).round(3)
    return res.sort_values(["severidade", "inicio_s"], key=lambda s: s.map(order) if s.name == "severidade" else s) \
              .reset_index(drop=True)
