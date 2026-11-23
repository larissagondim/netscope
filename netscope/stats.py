"""Estatísticas gerais de tráfego."""
from __future__ import annotations

import pandas as pd


def summary(df: pd.DataFrame) -> dict:
    if df.empty:
        return {"packets": 0, "bytes": 0, "duration": 0.0, "pps": 0.0, "bps": 0.0, "avg_size": 0.0,
                "hosts": 0, "first": None, "last": None}
    duration = float(df["time"].max() - df["time"].min())
    total_bytes = int(df["length"].sum())
    hosts = pd.concat([df["src_ip"], df["dst_ip"]]).dropna().nunique()
    return {
        "packets": len(df),
        "bytes": total_bytes,
        "duration": duration,
        "pps": len(df) / duration if duration > 0 else float(len(df)),
        "bps": total_bytes * 8 / duration if duration > 0 else float(total_bytes * 8),
        "avg_size": float(df["length"].mean()),
        "hosts": int(hosts),
        "first": df["timestamp"].min(),
        "last": df["timestamp"].max(),
    }


def protocol_distribution(df: pd.DataFrame) -> pd.DataFrame:
    """Pacotes e bytes por protocolo de mais alto nível identificado."""
    g = df.groupby("protocol").agg(pacotes=("no", "count"), bytes=("length", "sum")).reset_index()
    g["% pacotes"] = (100 * g["pacotes"] / g["pacotes"].sum()).round(2)
    g["% bytes"] = (100 * g["bytes"] / g["bytes"].sum()).round(2)
    return g.sort_values("pacotes", ascending=False).rename(columns={"protocol": "protocolo"})


def transport_distribution(df: pd.DataFrame) -> pd.DataFrame:
    t = df["transport"].fillna(df["protocol"].where(df["protocol"].isin(["ARP"]), "Outro"))
    return t.value_counts().rename_axis("transporte").reset_index(name="pacotes")


def top_ips(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Endereços IP mais ativos (enviados + recebidos)."""
    sent = df.groupby("src_ip").agg(pkts_enviados=("no", "count"), bytes_enviados=("length", "sum"))
    recv = df.groupby("dst_ip").agg(pkts_recebidos=("no", "count"), bytes_recebidos=("length", "sum"))
    t = sent.join(recv, how="outer").fillna(0).astype(int)
    t["pacotes"] = t["pkts_enviados"] + t["pkts_recebidos"]
    t["bytes"] = t["bytes_enviados"] + t["bytes_recebidos"]
    t.index.name = "ip"
    return t.sort_values("pacotes", ascending=False).head(n).reset_index()


def top_ports(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Portas de destino mais usadas, por protocolo de transporte."""
    d = df.dropna(subset=["dst_port"])
    if d.empty:
        return pd.DataFrame(columns=["transporte", "porta", "pacotes", "bytes", "servico"])
    g = (d.groupby(["transport", "dst_port"]).agg(pacotes=("no", "count"), bytes=("length", "sum"))
         .reset_index().rename(columns={"transport": "transporte", "dst_port": "porta"}))
    g["servico"] = g["porta"].map(lambda p: WELL_KNOWN.get(int(p), ""))
    return g.sort_values("pacotes", ascending=False).head(n)


def conversations(df: pd.DataFrame, n: int = 20) -> pd.DataFrame:
    """Conversas entre pares de IP (sem direção)."""
    d = df.dropna(subset=["src_ip", "dst_ip"]).copy()
    if d.empty:
        return pd.DataFrame()
    a = d[["src_ip", "dst_ip"]].min(axis=1)
    b = d[["src_ip", "dst_ip"]].max(axis=1)
    d["host_a"], d["host_b"] = a, b
    g = d.groupby(["host_a", "host_b"]).agg(
        pacotes=("no", "count"), bytes=("length", "sum"), inicio=("rel_time", "min"), fim=("rel_time", "max"),
        protocolos=("protocol", lambda s: ", ".join(sorted(set(s)))))
    g["duracao_s"] = (g["fim"] - g["inicio"]).round(3)
    return g.sort_values("bytes", ascending=False).head(n).reset_index()


def timeline(df: pd.DataFrame, bucket_s: float | None = None, by_protocol: bool = True) -> pd.DataFrame:
    """Série temporal de pacotes/bytes por intervalo."""
    if df.empty:
        return pd.DataFrame()
    duration = float(df["rel_time"].max())
    if bucket_s is None:
        bucket_s = auto_bucket(duration)
    d = df.copy()
    d["t"] = (d["rel_time"] // bucket_s) * bucket_s
    keys = ["t", "protocol"] if by_protocol else ["t"]
    g = d.groupby(keys).agg(pacotes=("no", "count"), bytes=("length", "sum")).reset_index()
    g["pps"] = g["pacotes"] / bucket_s
    g["bps"] = g["bytes"] * 8 / bucket_s
    return g


def auto_bucket(duration: float) -> float:
    for b in (0.01, 0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 3600):
        if duration / b <= 200:
            return b
    return 3600


def size_distribution(df: pd.DataFrame) -> pd.DataFrame:
    bins = [0, 64, 128, 256, 512, 1024, 1518, 10 ** 9]
    labels = ["≤64", "65–128", "129–256", "257–512", "513–1024", "1025–1518", ">1518"]
    c = pd.cut(df["length"], bins=bins, labels=labels, include_lowest=True)
    return c.value_counts(sort=False).rename_axis("faixa").reset_index(name="pacotes")


WELL_KNOWN = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 853: "DoT", 993: "IMAPS", 995: "POP3S",
    1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS", 5432: "PostgreSQL", 8080: "HTTP-alt",
    8443: "HTTPS-alt",
}
