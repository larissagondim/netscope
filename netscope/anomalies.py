"""Identificação de comportamentos potencialmente anômalos por regras (heurísticas).

Cada regra gera *indícios*, não confirmações de ataque. Todos os limiares são
configuráveis pela interface (``Thresholds``).

As contagens usam **janela deslizante**: uma ocorrência é detectada se existir
*qualquer* intervalo de ``window_s`` segundos que atinja o limiar, e não apenas
intervalos alinhados em 0, 10, 20 s… (janelas fixas deixam passar eventos que
cruzam a fronteira entre duas janelas). Janelas sobrepostas que disparam são
unidas em um único episódio, para que cada evento seja reportado uma vez.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Iterator

import numpy as np
import pandas as pd


@dataclass
class Thresholds:
    window_s: float = 10.0            # duração da janela deslizante
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

# Protocolos com formato de mensagem DNS. Não contam como "varredura" de portas UDP.
DNS_FAMILY = ["DNS", "MDNS", "LLMNR"]


def _flagset(s):
    return set(s.split(",")) if isinstance(s, str) and s else set()


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


# --------------------------------------------------------------------------- #
# Janela deslizante
# --------------------------------------------------------------------------- #
def episodes(times, values, w: float, threshold: int) -> list[tuple[int, int, int]]:
    """Encontra trechos em que alguma janela de ``w`` segundos tem ≥ ``threshold`` valores distintos.

    ``times`` deve estar em ordem crescente. Tudo em O(n), com ponteiros que só avançam:

    * ``tight``: para cada pacote ``right``, o menor trecho [tight, right] que ainda tem
      ``threshold`` valores distintos. Dispara se esse trecho couber em ``w`` segundos.
      Usar o trecho mínimo (e não a janela inteira de ``w``) faz o episódio começar e
      terminar no próprio evento, sem arrastar pacotes normais vizinhos.
    * ``left``: início da janela de ``w`` segundos que termina em ``right``, usada só para
      medir o pico de valores distintos.

    Trechos que disparam e se sobrepõem são unidos. Retorna ``(inicio, fim, pico)``:
    índices inclusivos do episódio e o maior número de valores distintos em uma janela.
    """
    def drop(cnt, v):
        cnt[v] -= 1
        if not cnt[v]:
            del cnt[v]

    win: Counter = Counter()   # janela de w segundos
    tc: Counter = Counter()    # trecho mínimo
    left = tight = 0
    out: list[list[int]] = []
    for right in range(len(times)):
        v = values[right]
        win[v] += 1
        tc[v] += 1
        while times[right] - times[left] > w:
            drop(win, values[left])
            left += 1
        # encolhe o trecho enquanto continuar com ≥ threshold valores distintos
        while tight < right and (tc[values[tight]] > 1 or len(tc) > threshold):
            drop(tc, values[tight])
            tight += 1
        if len(tc) >= threshold and times[right] - times[tight] <= w:
            if out and tight <= out[-1][1]:
                out[-1][1] = right
                out[-1][2] = max(out[-1][2], len(win))
            else:
                out.append([tight, right, len(win)])
    return [tuple(e) for e in out]


def _sliding(df: pd.DataFrame, keys: list[str], value: str | None, w: float,
             threshold: int) -> Iterator[tuple[tuple, pd.DataFrame, int]]:
    """Para cada grupo ``keys``, gera ``(chave, pacotes do episódio, pico)``.

    Com ``value=None`` conta pacotes; caso contrário, valores distintos da coluna ``value``.
    """
    if df.empty:
        return
    d = df.sort_values("rel_time", kind="stable")
    for key, g in d.groupby(keys, sort=False, dropna=True):
        if len(g) < threshold:
            continue
        times = g["rel_time"].to_numpy()
        vals = np.arange(len(g)) if value is None else g[value].to_numpy()
        for i0, i1, peak in episodes(times, vals, w, threshold):
            yield (key if isinstance(key, tuple) else (key,)), g.iloc[i0:i1 + 1], peak


def _span(ep: pd.DataFrame, trim: bool = False) -> tuple[float, float]:
    """Início e fim do episódio. Com ``trim``, usa os quantis 5% e 95%: em regras de volume, o episódio
    inclui alguns pacotes normais vizinhos à rajada, e o recorte mostra o período da rajada em si."""
    t = ep["rel_time"]
    if trim:
        return float(t.quantile(0.05)), float(t.quantile(0.95))
    return float(t.min()), float(t.max())


# --------------------------------------------------------------------------- #
# Regras
# --------------------------------------------------------------------------- #
def detect_port_scan(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    """Muitas portas distintas acessadas por uma origem em curto intervalo."""
    out = []
    d = df[df["transport"].isin(["TCP", "UDP"])]
    if d.empty:
        return out
    # Para TCP considera apenas tentativas de conexão (SYN sem ACK); para UDP, qualquer datagrama
    is_syn = d["tcp_flags"].map(lambda s: "SYN" in _flagset(s) and "ACK" not in _flagset(s))
    d = d[(d["transport"] == "UDP") | is_syn]
    d = d[~d["protocol"].isin(DNS_FAMILY)]

    # Varredura vertical: muitas portas em um mesmo host
    for (src, dst), ep, peak in _sliding(d, ["src_ip", "dst_ip"], "dst_port", th.window_s, th.scan_ports):
        ini, fim = _span(ep)
        portas = sorted(set(ep["dst_port"].dropna().astype(int)))
        out.append({
            "severidade": "Alta" if len(portas) >= 3 * th.scan_ports else "Média",
            "tipo": "Varredura de portas",
            "origem": src, "alvo": dst, "inicio_s": ini, "fim_s": fim,
            "evidencia": f"{len(portas)} portas distintas em {fim - ini:.2f}s ({len(ep)} pacotes; "
                         f"pico de {peak} em {th.window_s:g}s). Ex.: {', '.join(map(str, portas[:10]))}…",
            "descricao": "Uma única origem tentou contato com muitas portas do mesmo destino em pouco tempo, "
                         "padrão típico de ferramentas de varredura (ex.: nmap -sS).",
        })

    # Varredura horizontal: mesma porta em muitos hosts
    for (src, port), ep, peak in _sliding(d, ["src_ip", "dst_port"], "dst_ip", th.window_s, th.scan_hosts):
        ini, fim = _span(ep)
        out.append({
            "severidade": "Média", "tipo": "Varredura de hosts",
            "origem": src, "alvo": f"porta {port}", "inicio_s": ini, "fim_s": fim,
            "evidencia": f"{ep['dst_ip'].nunique()} hosts distintos contatados na porta {port} em {fim - ini:.2f}s "
                         f"(pico de {peak} em {th.window_s:g}s)",
            "descricao": "Uma origem tentou acessar o mesmo serviço em muitos hosts (varredura horizontal).",
        })
    return out


def detect_syn_flood(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    """Quantidade elevada de SYN sem a correspondente resposta/conclusão do handshake."""
    out = []
    t = df[df["transport"] == "TCP"]
    if t.empty:
        return out
    fl = t["tcp_flags"].map(_flagset)
    syn = t[fl.map(lambda f: "SYN" in f and "ACK" not in f)]
    synack = t[fl.map(lambda f: {"SYN", "ACK"} <= f)]
    grace = min(1.0, th.window_s)  # margem para as respostas aos últimos SYN do episódio
    for (dst,), ep, peak in _sliding(syn, ["dst_ip"], None, th.window_s, th.syn_count):
        ini, fim = _span(ep, trim=True)
        syns, origens, portas = len(ep), ep["src_ip"].nunique(), ep["dst_port"].nunique()
        # Origem única tocando muitas portas = varredura (já reportada por detect_port_scan)
        if origens == 1 and portas >= th.scan_ports:
            continue
        t0, t1 = _span(ep)
        sa = int(((synack["src_ip"] == dst) & synack["rel_time"].between(t0, t1 + grace)).sum())
        ratio = syns / max(sa, 1)
        if ratio < th.syn_ratio:
            continue
        spoof = origens > 0.5 * syns
        out.append({
            "severidade": "Alta",
            "tipo": "Excesso de SYN (possível SYN flood)",
            "origem": f"{origens} origens distintas" if origens > 1 else ep["src_ip"].iloc[0],
            "alvo": dst, "inicio_s": ini, "fim_s": fim,
            "evidencia": f"{syns} SYN vs {sa} SYN-ACK (razão {ratio:.1f}); "
                         f"pico de {peak} SYN em {th.window_s:g}s"
                         + ("; muitas origens distintas (possível IP falsificado)" if spoof else ""),
            "descricao": "Grande volume de pedidos de conexão sem conclusão do three-way handshake, "
                         "o que pode esgotar a fila de conexões semiabertas do servidor.",
        })
    return out


def detect_dns_anomalies(df: pd.DataFrame, th: Thresholds) -> list[dict]:
    out = []
    d = df[(df["protocol"] == "DNS")]
    if d.empty or "dns_is_response" not in d:
        return out
    q = d[d["dns_is_response"] == False].copy()  # noqa: E712
    if not q.empty:
        # 1) Taxa elevada de consultas
        for (src,), ep, peak in _sliding(q, ["src_ip"], None, th.window_s, th.dns_rate):
            ini, fim = _span(ep, trim=True)
            out.append({
                "severidade": "Média", "tipo": "Volume elevado de consultas DNS",
                "origem": src, "alvo": "servidores DNS", "inicio_s": ini, "fim_s": fim,
                "evidencia": f"{len(ep)} consultas ({ep['dns_qname'].nunique()} nomes distintos); "
                             f"pico de {peak} em {th.window_s:g}s",
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
    i = df[df["transport"] == "ICMP"]
    for (src, dst), ep, peak in _sliding(i, ["src_ip", "dst_ip"], None, th.window_s, th.icmp_rate):
        ini, fim = _span(ep)
        out.append({
            "severidade": "Média", "tipo": "Volume elevado de ICMP",
            "origem": src, "alvo": dst, "inicio_s": ini, "fim_s": fim,
            "evidencia": f"{len(ep)} pacotes ICMP em {fim - ini:.2f}s; pico de {peak} em {th.window_s:g}s",
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
