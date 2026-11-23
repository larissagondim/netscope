"""Inspeção de um pacote camada a camada (encapsulamento)."""
from __future__ import annotations

from scapy.packet import NoPayload, Packet, Raw
from scapy.utils import hexdump

# Mapeamento aproximado das camadas do Scapy para o modelo TCP/IP
LAYER_MODEL = {
    "Ethernet": "Enlace", "802.3": "Enlace", "cooked linux": "Enlace", "cooked linux v2": "Enlace",
    "802.1Q": "Enlace", "ARP": "Enlace / Rede",
    "IP": "Rede", "IPv6": "Rede", "ICMP": "Rede", "IP in ICMP": "Rede",
    "TCP": "Transporte", "UDP": "Transporte", "TCP in ICMP": "Transporte", "UDP in ICMP": "Transporte",
    "DNS": "Aplicação", "Raw": "Dados (payload)", "Padding": "Enchimento",
}


def model_layer(name: str) -> str:
    if name in LAYER_MODEL:
        return LAYER_MODEL[name]
    if name.startswith("ICMPv6") or name.startswith("ICMP"):
        return "Rede"
    if name.startswith("DNS"):
        return "Aplicação"
    return "Aplicação"


def layers(pkt: Packet) -> list[dict]:
    """Lista as camadas do pacote com tamanho de cabeçalho, offset e campos."""
    out = []
    offset = 0
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        total = len(layer)
        payload_len = len(layer.payload) if not isinstance(layer.payload, NoPayload) else 0
        header_len = total - payload_len
        # Camadas "folha" como DNS/Raw: cabeçalho = tudo
        fields = []
        for f in layer.fields_desc:
            try:
                val = layer.getfieldval(f.name)
                shown = f.i2repr(layer, val)
            except Exception:  # noqa: BLE001
                shown = "?"
            if isinstance(shown, bytes):
                shown = shown.decode("latin-1", errors="replace")
            shown = str(shown)
            if len(shown) > 300:
                shown = shown[:300] + "…"
            fields.append({"Campo": f.name, "Valor": shown})
        name = layer.name
        if isinstance(layer, Raw):
            name = "Raw"
        out.append({
            "name": name,
            "model": model_layer(name),
            "offset": offset,
            "header_len": header_len,
            "total_len": total,
            "fields": fields,
        })
        offset += header_len
        layer = layer.payload
    return out


def hex_dump(pkt: Packet) -> str:
    return hexdump(pkt, dump=True)
