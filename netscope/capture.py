"""Captura de tráfego em tempo real (opcional).

Requer privilégios de administrador (root / Administrador) e, no Windows, o Npcap.
"""
from __future__ import annotations

from scapy.all import get_if_list, sniff, wrpcap


def interfaces() -> list[str]:
    try:
        return get_if_list()
    except Exception:  # noqa: BLE001
        return []


def live_capture(iface: str | None = None, count: int = 500, timeout: int = 30, bpf: str | None = None):
    """Captura pacotes da interface e retorna a lista de pacotes Scapy."""
    return list(sniff(iface=iface or None, count=count, timeout=timeout, filter=bpf or None, store=True))


def save(packets, path: str) -> None:
    wrpcap(path, packets)
