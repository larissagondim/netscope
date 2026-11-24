"""Análises específicas por protocolo: DNS, TCP (handshake), HTTP e TLS."""
from __future__ import annotations

import pandas as pd


def _cols(df: pd.DataFrame, cols: list[str]) -> pd.DataFrame:
    """Seleciona colunas, criando vazias as que não existirem na captura."""
    d = df.copy()
    for c in cols:
        if c not in d:
            d[c] = None
    return d[cols]


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def dns_transactions(df: pd.DataFrame) -> pd.DataFrame:
    """Associa cada consulta DNS à sua resposta (mesmo ID, cliente e servidor).

    Retorna uma linha por consulta, com resposta, código de retorno e tempo de resposta.
    """
    d = df[df["protocol"] == "DNS"]
    if d.empty:
        return pd.DataFrame()
    d = _cols(d, ["no", "rel_time", "src_ip", "dst_ip", "src_port", "dst_port", "dns_id", "dns_is_response",
                  "dns_qname", "dns_qtype", "dns_rcode", "dns_answers"])
    q = d[d["dns_is_response"] == False]  # noqa: E712
    r = d[d["dns_is_response"] == True]  # noqa: E712
    q = q.rename(columns={"src_ip": "cliente", "dst_ip": "servidor", "src_port": "porta_cliente"})
    r = r.rename(columns={"dst_ip": "cliente", "src_ip": "servidor", "dst_port": "porta_cliente"})
    keys = ["cliente", "servidor", "porta_cliente", "dns_id"]
    q = q.sort_values("rel_time")
    r = r.sort_values("rel_time")
    # primeira resposta posterior à consulta com a mesma chave
    m = pd.merge_asof(q, r[keys + ["rel_time", "no", "dns_rcode", "dns_answers"]].rename(
        columns={"rel_time": "t_resp", "no": "no_resp", "dns_rcode": "rcode", "dns_answers": "respostas"}),
        left_on="rel_time", right_on="t_resp", by=keys, direction="forward")
    m["tempo_resposta_ms"] = ((m["t_resp"] - m["rel_time"]) * 1000).round(2)
    m["status"] = m["rcode"].fillna("SEM RESPOSTA")
    out = m[["no", "rel_time", "cliente", "servidor", "dns_id", "dns_qname", "dns_qtype", "status", "respostas",
             "tempo_resposta_ms", "no_resp"]].rename(columns={
        "no": "pacote", "rel_time": "tempo_s", "dns_id": "id", "dns_qname": "nome", "dns_qtype": "tipo"})
    out["id"] = out["id"].map(lambda x: f"0x{int(x):04x}" if pd.notna(x) else None)
    return out.reset_index(drop=True)


def dns_summary(tx: pd.DataFrame) -> dict:
    if tx.empty:
        return {}
    answered = tx["status"] != "SEM RESPOSTA"
    return {
        "consultas": len(tx),
        "respondidas": int(answered.sum()),
        "sem_resposta": int((~answered).sum()),
        "nxdomain": int((tx["status"] == "NXDOMAIN").sum()),
        "tempo_medio_ms": float(tx["tempo_resposta_ms"].mean()) if answered.any() else None,
        "dominios_unicos": int(tx["nome"].nunique()),
    }


# --------------------------------------------------------------------------- #
# TCP
# --------------------------------------------------------------------------- #
def _flags(s) -> set[str]:
    return set(s.split(",")) if isinstance(s, str) and s else set()


def tcp_sessions(df: pd.DataFrame) -> pd.DataFrame:
    """Reconstrói o estado de cada conexão TCP (fluxo bidirecional).

    Para cada fluxo identifica: SYN, SYN-ACK e ACK do three-way handshake,
    RTT do handshake, encerramento por FIN ou RST, pacotes e bytes.

    A mesma 4-tupla (IPs + portas) pode ser reutilizada por conexões sucessivas.
    Um SYN novo inicia outra sessão quando a anterior já foi encerrada (FIN/RST),
    quando o número de sequência inicial (ISN) difere do SYN já visto, ou quando
    a sessão anterior foi observada já em andamento. Um SYN retransmitido
    (mesmo ISN, conexão ainda aberta) continua na mesma sessão.
    """
    t = df[df["transport"] == "TCP"]
    if t.empty:
        return pd.DataFrame()
    active: dict = {}   # 4-tupla -> sessão corrente
    sessions = []       # todas as sessões, em ordem de criação
    for r in t.itertuples(index=False):
        a = (r.src_ip, int(r.src_port))
        b = (r.dst_ip, int(r.dst_port))
        key = (a, b) if a <= b else (b, a)
        s = active.get(key)
        flags = _flags(r.tcp_flags)
        is_syn = "SYN" in flags and "ACK" not in flags
        seq = int(r.tcp_seq) if pd.notna(r.tcp_seq) else None
        if s is not None and is_syn:
            closed = s["fin"] or s["rst"]
            other_isn = s["isn"] is not None and seq != s["isn"]
            midstream = s["isn"] is None
            if closed or other_isn or midstream:
                s = None  # reuso da 4-tupla: nova conexão
        if s is None:
            s = active[key] = {
                "cliente": None, "porta_cliente": None, "servidor": None, "porta_servidor": None,
                "inicio": r.rel_time, "fim": r.rel_time, "pacotes": 0, "bytes": 0, "payload": 0,
                "t_syn": None, "t_synack": None, "t_ack": None, "fin": 0, "rst": 0, "isn": None,
                "_seen_by": a, "_key": key,
            }
            sessions.append(s)
        s["pacotes"] += 1
        s["bytes"] += r.length
        s["payload"] += r.payload_len or 0
        s["fim"] = r.rel_time
        if "SYN" in flags and "ACK" not in flags:
            if s["t_syn"] is None:
                s["t_syn"] = r.rel_time
                s["isn"] = seq
                s["cliente"], s["porta_cliente"] = a
                s["servidor"], s["porta_servidor"] = b
        elif "SYN" in flags and "ACK" in flags:
            if s["t_synack"] is None and (s["cliente"] is None or a == (s["servidor"], s["porta_servidor"])):
                s["t_synack"] = r.rel_time
                if s["cliente"] is None:  # SYN não capturado
                    s["cliente"], s["porta_cliente"] = b
                    s["servidor"], s["porta_servidor"] = a
        elif "ACK" in flags and s["t_synack"] is not None and s["t_ack"] is None \
                and a == (s["cliente"], s["porta_cliente"]):
            s["t_ack"] = r.rel_time
        if "FIN" in flags:
            s["fin"] += 1
        if "RST" in flags:
            s["rst"] += 1

    out = []
    for s in sessions:
        key = s["_key"]
        if s["cliente"] is None:  # sem SYN/SYN-ACK: assume quem foi visto primeiro como cliente
            (s["cliente"], s["porta_cliente"]), other = s["_seen_by"], (key[1] if key[0] == s["_seen_by"] else key[0])
            s["servidor"], s["porta_servidor"] = other
        syn, synack, ack = s["t_syn"] is not None, s["t_synack"] is not None, s["t_ack"] is not None
        if syn and synack and ack:
            hs = "Completo"
        elif syn and synack:
            hs = "SYN + SYN-ACK (sem ACK)"
        elif syn:
            hs = "Apenas SYN"
        elif synack:
            hs = "SYN não capturado"
        else:
            hs = "Já estabelecida"
        if s["rst"]:
            end = "RST"
        elif s["fin"] >= 2:
            end = "FIN (encerrada)"
        elif s["fin"] == 1:
            end = "FIN (meio-fechada)"
        else:
            end = "Aberta / não observada"
        out.append({
            "cliente": s["cliente"], "porta_cliente": s["porta_cliente"],
            "servidor": s["servidor"], "porta_servidor": s["porta_servidor"],
            "handshake": hs,
            "rtt_handshake_ms": round((s["t_synack"] - s["t_syn"]) * 1000, 3) if syn and synack else None,
            "encerramento": end,
            "pacotes": s["pacotes"], "bytes": s["bytes"], "bytes_payload": s["payload"],
            "inicio_s": round(s["inicio"], 6), "duracao_s": round(s["fim"] - s["inicio"], 6),
        })
    return pd.DataFrame(out).sort_values("inicio_s").reset_index(drop=True)


def tcp_flag_counts(df: pd.DataFrame) -> pd.DataFrame:
    t = df[df["transport"] == "TCP"]["tcp_flags"].dropna()
    counts = {}
    for f in ("SYN", "ACK", "FIN", "RST", "PSH", "URG"):
        counts[f] = int(t.map(lambda s: f in _flags(s)).sum())
    counts["SYN (sem ACK)"] = int(t.map(lambda s: _flags(s) >= {"SYN"} and "ACK" not in _flags(s)).sum())
    counts["SYN-ACK"] = int(t.map(lambda s: {"SYN", "ACK"} <= _flags(s)).sum())
    return pd.DataFrame({"flag": list(counts), "pacotes": list(counts.values())})


# --------------------------------------------------------------------------- #
# HTTP / TLS
# --------------------------------------------------------------------------- #
def http_messages(df: pd.DataFrame) -> pd.DataFrame:
    h = df[df["protocol"] == "HTTP"]
    if h.empty:
        return pd.DataFrame()
    return _cols(h, ["no", "rel_time", "src_ip", "src_port", "dst_ip", "dst_port", "http_type", "http_method",
                     "http_host", "http_uri", "http_status", "http_reason", "http_user_agent",
                     "http_content_type"]).rename(columns={"no": "pacote", "rel_time": "tempo_s"}).reset_index(drop=True)


def tls_handshakes(df: pd.DataFrame) -> pd.DataFrame:
    t = df[(df["protocol"] == "TLS")]
    if t.empty or "tls_handshake" not in t:
        return pd.DataFrame()
    t = t[t["tls_handshake"].isin(["ClientHello", "ServerHello"])]
    return _cols(t, ["no", "rel_time", "src_ip", "src_port", "dst_ip", "dst_port", "tls_handshake", "tls_version",
                     "tls_record_version", "tls_sni"]).rename(
        columns={"no": "pacote", "rel_time": "tempo_s"}).reset_index(drop=True)


def tls_servers(df: pd.DataFrame) -> pd.DataFrame:
    """Servidores (SNI) acessados via TLS e versão negociada."""
    hs = tls_handshakes(df)
    if hs.empty:
        return hs
    keys = ["src_ip", "src_port", "dst_ip", "dst_port"]
    ch = hs[hs["tls_handshake"] == "ClientHello"].sort_values("tempo_s")
    sh = hs[hs["tls_handshake"] == "ServerHello"][keys + ["tempo_s", "tls_version"]]
    sh = sh.rename(columns={"src_ip": "dst_ip", "src_port": "dst_port", "dst_ip": "src_ip", "dst_port": "src_port",
                            "tempo_s": "t_sh", "tls_version": "versao_negociada"}).sort_values("t_sh")
    # Cada ClientHello casa com o primeiro ServerHello posterior na mesma 4-tupla. Um merge só pela
    # 4-tupla multiplicaria as linhas quando as portas são reutilizadas por conexões sucessivas.
    m = pd.merge_asof(ch, sh, left_on="tempo_s", right_on="t_sh", by=keys, direction="forward")
    return (m.groupby(["tls_sni", "dst_ip"], dropna=False)
            .agg(conexoes=("pacote", "count"),
                 versao_negociada=("versao_negociada", lambda s: ", ".join(sorted(set(s.dropna()))) or "?"))
            .reset_index().rename(columns={"tls_sni": "sni", "dst_ip": "servidor"})
            .sort_values("conexoes", ascending=False))
