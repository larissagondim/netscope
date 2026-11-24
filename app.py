"""NetScope — interface Streamlit.

Execute com:  streamlit run app.py
"""
from __future__ import annotations

import io
import os
import tempfile
import zipfile
from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from netscope import anomalies, packet_view, protocols, stats
from netscope.parser import Capture, load_packets, load_pcap, rebuild_packet

ROOT = Path(__file__).parent
st.set_page_config(page_title="NetScope", page_icon=str(ROOT / "assets" / "netscope.svg"), layout="wide")
st.html(ROOT / "assets" / "netscope.css")

CHART_COLORS = ["#202020", "#606060", "#979797", "#bcbcbc", "#454545", "#767676", "#d5d5d5"]
px.defaults.color_discrete_sequence = CHART_COLORS

EXAMPLE = Path(__file__).parent / "exemplos" / "exemplo_netscope.pcap"
LAYER_COLORS = {
    "Enlace": "#292929", "Enlace / Rede": "#444444", "Rede": "#5c5c5c",
    "Transporte": "#737373", "Aplicação": "#929292", "Dados (payload)": "#b5b5b5",
    "Enchimento": "#d6d6d6",
}
SEV_COLORS = {"Alta": "#171717", "Média": "#6b6b6b", "Baixa": "#acacac"}
BRAND_ICON = (ROOT / "assets" / "netscope.svg").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# Carregamento (com cache)
# --------------------------------------------------------------------------- #
@st.cache_data(show_spinner="Lendo e interpretando pacotes…", max_entries=4)
def parse_bytes(data: bytes, max_packets: int | None) -> Capture:
    return load_pcap(data, max_packets=max_packets)


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:,.1f} TB"


def fmt_rate(bps: float) -> str:
    for unit in ("bit/s", "kbit/s", "Mbit/s", "Gbit/s"):
        if abs(bps) < 1000:
            return f"{bps:,.1f} {unit}"
        bps /= 1000
    return f"{bps:,.1f} Tbit/s"


def csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")  # BOM: abre corretamente no Excel


def download(df: pd.DataFrame, name: str, label: str = "⬇Exportar CSV", key: str | None = None):
    st.download_button(label, csv_bytes(df), file_name=name, mime="text/csv", key=key or f"dl_{name}",
                       disabled=df.empty, icon=":material/download:")


# --------------------------------------------------------------------------- #
# Barra lateral: fonte de dados
# --------------------------------------------------------------------------- #
st.sidebar.html(
    f'<div class="ns-brand">{BRAND_ICON}<span>NetScope</span></div>'
)
st.sidebar.subheader("Captura")

source = st.sidebar.radio(
    "Fonte dos dados", ["Arquivo PCAP", "Exemplo incluído", "Captura ao vivo"], key="capture_source"
)
max_pk = st.sidebar.number_input("Limite de pacotes (0 = sem limite)", min_value=0, value=0, step=10000,
                                 help="Útil para capturas muito grandes.")
max_pk = int(max_pk) or None

capture: Capture | None = None
source_name = ""

if source == "Arquivo PCAP":
    up = st.sidebar.file_uploader("Envie um arquivo .pcap / .pcapng", type=["pcap", "pcapng", "cap"])
    if up is not None:
        try:
            capture = parse_bytes(up.getvalue(), max_pk)
            source_name = up.name
        except Exception as exc:  # noqa: BLE001
            st.sidebar.error(f"Não foi possível ler o arquivo: {exc}")
elif source == "Exemplo incluído":
    if not EXAMPLE.exists():
        from scripts.gerar_pcap_exemplo import main as gerar
        EXAMPLE.parent.mkdir(exist_ok=True)
        gerar(str(EXAMPLE))
    capture = parse_bytes(EXAMPLE.read_bytes(), max_pk)
    source_name = EXAMPLE.name
else:
    from netscope import capture as live

    st.sidebar.caption("Requer privilégios de administrador (sudo) e, no Windows, o Npcap.")
    ifaces = live.interfaces()
    iface = st.sidebar.selectbox("Interface", ["(padrão)"] + ifaces)
    count = st.sidebar.number_input("Nº de pacotes", 10, 100000, 500, step=100)
    timeout = st.sidebar.number_input("Tempo máximo (s)", 1, 3600, 30)
    bpf = st.sidebar.text_input("Filtro BPF (opcional)", placeholder="ex.: tcp port 80 or udp port 53")
    if st.sidebar.button("▶Iniciar captura", type="primary"):
        try:
            with st.spinner(f"Capturando até {count} pacotes por {timeout}s…"):
                pkts = live.live_capture(None if iface == "(padrão)" else iface, int(count), int(timeout), bpf)
            st.session_state["live"] = load_packets(pkts)
            buf = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            buf.close()
            live.save(pkts, buf.name)
            st.session_state["live_pcap"] = Path(buf.name).read_bytes()
            os.unlink(buf.name)
        except PermissionError:
            st.sidebar.error("Permissão negada. Execute o Streamlit com sudo/Administrador.")
        except Exception as exc:  # noqa: BLE001
            st.sidebar.error(f"Falha na captura: {exc}")
    capture = st.session_state.get("live")
    source_name = "captura_ao_vivo.pcap"
    if st.session_state.get("live_pcap"):
        st.sidebar.download_button("Salvar captura (.pcap)", st.session_state["live_pcap"],
                                   file_name="captura_netscope.pcap", icon=":material/download:")

if capture is None or capture.df.empty:
    if capture is not None:
        title = "Captura sem pacotes"
        detail = "Escolha outra captura ou verifique a interface e o filtro BPF."
    elif source == "Captura ao vivo":
        title = "Capture o tráfego da rede"
        detail = "Configure a interface e inicie a captura na barra lateral."
    else:
        title = "Abra uma captura de rede"
        detail = "Selecione um arquivo PCAP ou PCAPNG na barra lateral."
    st.html(
        f'<section class="ns-empty">{BRAND_ICON}'
        f'<h1>{title}</h1><p>{detail}</p></section>'
    )
    if source == "Arquivo PCAP" and capture is None:
        st.button(
            "Abrir exemplo", icon=":material/folder_open:",
            on_click=st.session_state.__setitem__, args=("capture_source", "Exemplo incluído"),
        )
    st.stop()

full = capture.df

# --------------------------------------------------------------------------- #
# Filtros globais
# --------------------------------------------------------------------------- #
st.sidebar.divider()
st.sidebar.subheader("Filtros")
protos = sorted(full["protocol"].dropna().unique())
sel_protos = st.sidebar.multiselect("Protocolos", protos, default=[], placeholder="Todos")
ip_f = st.sidebar.text_input("Endereço IP (origem ou destino)", placeholder="ex.: 192.168.0.10")
port_f = st.sidebar.text_input("Porta (origem ou destino)", placeholder="ex.: 443")
tmax = float(full["rel_time"].max()) if len(full) else 0.0
t_range = st.sidebar.slider("Intervalo de tempo (s)", 0.0, max(tmax, 0.001), (0.0, max(tmax, 0.001)))
text_f = st.sidebar.text_input("Buscar no campo Info", placeholder="ex.: SYN, GET, example.org")

df = full
if sel_protos:
    df = df[df["protocol"].isin(sel_protos)]
if ip_f.strip():
    ip_s = ip_f.strip()
    df = df[(df["src_ip"] == ip_s) | (df["dst_ip"] == ip_s)]
if port_f.strip().isdigit():
    p = int(port_f)
    df = df[(df["src_port"] == p) | (df["dst_port"] == p)]
df = df[(df["rel_time"] >= t_range[0]) & (df["rel_time"] <= t_range[1])]
if text_f.strip():
    df = df[df["info"].str.contains(text_f.strip(), case=False, na=False, regex=False)]

filtered = len(df) != len(full)

# --------------------------------------------------------------------------- #
# Cabeçalho e métricas
# --------------------------------------------------------------------------- #
packet_count = f"{len(df):,} de {len(full):,} pacotes" if filtered else f"{len(full):,} pacotes"
st.html(
    f'<header class="ns-capture"><div class="ns-capture-name">'
    f'{BRAND_ICON}<h1>{escape(source_name)}</h1></div>'
    f'<span class="ns-count">{packet_count}</span></header>'
)

if df.empty:
    st.warning("Nenhum pacote corresponde aos filtros selecionados.")
    st.stop()

summ = stats.summary(df)
with st.container(key="capture_metrics"):
    first, second = st.columns(2)
    c = [*first.columns(3), *second.columns(3)]
    c[0].metric("Pacotes", f"{summ['packets']:,}")
    c[1].metric("Bytes", fmt_bytes(summ["bytes"]))
    c[2].metric("Duração", f"{summ['duration']:.2f} s")
    c[3].metric("Taxa média", fmt_rate(summ["bps"]))
    c[4].metric("Pacotes/s", f"{summ['pps']:,.1f}")
    c[5].metric("Hosts (IPs)", summ["hosts"])

tabs = st.tabs([
    ":material/analytics: Visão geral", ":material/table_rows: Pacotes",
    ":material/layers: Inspeção", ":material/lan: Protocolos",
    ":material/warning: Anomalias", ":material/download: Exportar",
])

# --------------------------------------------------------------------------- #
# 1. Visão geral
# --------------------------------------------------------------------------- #
with tabs[0]:
    dist = stats.protocol_distribution(df)
    col1, col2 = st.columns([2, 3])
    with col1:
        metric = st.radio("Medida", ["pacotes", "bytes"], horizontal=True, key="dist_metric")
        fig = px.pie(dist, names="protocolo", values=metric, hole=0.45, title=f"Distribuição de protocolos ({metric})")
        fig.update_traces(textinfo="percent+label", marker_line_width=1, marker_line_color="#fff")
        st.plotly_chart(fig)
    with col2:
        bucket = stats.auto_bucket(summ["duration"])
        tl = stats.timeline(df, bucket)
        ycol = st.radio("Eixo Y", ["pacotes", "bytes"], horizontal=True, key="tl_metric")
        fig = px.area(tl, x="t", y=ycol, color="protocol", pattern_shape="protocol",
                      title=f"Tráfego ao longo do tempo (intervalos de {bucket:g}s)",
                      labels={"t": "tempo (s)", "protocol": "protocolo"})
        st.plotly_chart(fig)

    col1, col2 = st.columns(2)
    with col1:
        tip = stats.top_ips(df, 10)
        fig = px.bar(tip.sort_values("pacotes"), x=["pkts_enviados", "pkts_recebidos"], y="ip", orientation="h",
                     title="Top 10 endereços IP (pacotes)", labels={"value": "pacotes", "variable": ""})
        st.plotly_chart(fig)
    with col2:
        tp = stats.top_ports(df, 10)
        if not tp.empty:
            tp["rotulo"] = tp.apply(lambda r: f"{r.transporte}/{r.porta}" + (f" ({r.servico})" if r.servico else ""),
                                    axis=1)
            fig = px.bar(tp.sort_values("pacotes"), x="pacotes", y="rotulo", color="transporte", pattern_shape="transporte", orientation="h",
                         title="Top 10 portas de destino", labels={"rotulo": ""})
            st.plotly_chart(fig)
        else:
            st.info("Nenhuma porta TCP/UDP nos pacotes filtrados.")

    col1, col2 = st.columns(2)
    with col1:
        sd = stats.size_distribution(df)
        st.plotly_chart(px.bar(sd, x="faixa", y="pacotes", title="Distribuição do tamanho dos pacotes (bytes)"))
    with col2:
        st.plotly_chart(px.bar(stats.transport_distribution(df), x="transporte", y="pacotes",
                               title="Protocolos de transporte"))

    st.subheader("Conversas entre hosts")
    conv = stats.conversations(df, 50)
    st.dataframe(conv, hide_index=True)
    st.subheader("Resumo por protocolo")
    st.dataframe(dist, hide_index=True)

# --------------------------------------------------------------------------- #
# 2. Lista de pacotes
# --------------------------------------------------------------------------- #
PACKET_COLS = ["no", "rel_time", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "length", "info"]
with tabs[1]:
    st.caption("Selecione uma linha e abra a aba Inspeção.")
    view = df[PACKET_COLS].rename(columns={
        "no": "Nº", "rel_time": "Tempo (s)", "src_ip": "Origem", "src_port": "Porta orig.", "dst_ip": "Destino",
        "dst_port": "Porta dest.", "protocol": "Protocolo", "length": "Tamanho", "info": "Info"})
    event = st.dataframe(view, hide_index=True, height=520, on_select="rerun", selection_mode="single-row",
                         key="pkt_table", column_config={"Tempo (s)": st.column_config.NumberColumn(format="%.6f")})
    rows = event.selection.rows if event and hasattr(event, "selection") else []
    if rows:
        st.session_state["selected_no"] = int(view.iloc[rows[0]]["Nº"])
    download(df.drop(columns=["timestamp"], errors="ignore"), "pacotes.csv", "⬇Exportar pacotes filtrados (CSV)")

# --------------------------------------------------------------------------- #
# 3. Inspeção de pacote
# --------------------------------------------------------------------------- #
with tabs[2]:
    default_no = st.session_state.get("selected_no")
    if default_no is None or not df["no"].eq(default_no).any():
        default_no = int(df["no"].iloc[0])
    no = st.number_input("Número do pacote", min_value=1, max_value=len(capture.raw), value=default_no,
                         key=f"insp_{default_no}")
    pkt = rebuild_packet(capture, int(no) - 1)
    row = full.iloc[int(no) - 1]
    st.markdown(f"**Pacote {no}** · {row['length']} bytes · t = {row['rel_time']:.6f}s · `{row['info']}`")

    lys = packet_view.layers(pkt)
    # Diagrama de encapsulamento: segmentos proporcionais ao tamanho de cada cabeçalho
    fig = go.Figure()
    for ly in lys:
        if ly["header_len"] <= 0:
            continue
        fig.add_bar(y=["quadro"], x=[ly["header_len"]], orientation="h", name=f"{ly['name']} ({ly['model']})",
                    marker_color=LAYER_COLORS.get(ly["model"], "#888"),
                    text=f"{ly['name']}<br>{ly['header_len']} B", textposition="inside", insidetextanchor="middle",
                    hovertemplate=f"{ly['name']}<br>bytes {ly['offset']}–{ly['offset'] + ly['header_len'] - 1}"
                                  f"<br>camada: {ly['model']}<extra></extra>")
    fig.update_layout(barmode="stack", height=230, title="Encapsulamento: bytes do quadro por camada",
                      xaxis_title="bytes", yaxis_visible=False, margin=dict(t=40, b=10),
                      legend=dict(orientation="h", yanchor="top", y=-0.45, traceorder="normal"))
    st.plotly_chart(fig)

    st.markdown("##### Pilha de protocolos")
    stack_cols = st.columns(len(lys))
    for col, ly in zip(stack_cols, lys):
        col.markdown(
            f"<div style='border-left:6px solid {LAYER_COLORS.get(ly['model'], '#888')};padding:4px 8px'>"
            f"<b>{ly['name']}</b><br><small>{ly['model']}<br>cabeçalho: {ly['header_len']} B<br>"
            f"offset: {ly['offset']}</small></div>", unsafe_allow_html=True)

    st.markdown("##### Campos dos cabeçalhos")
    for i, ly in enumerate(lys):
        with st.expander(f"{ly['name']} — {ly['model']} · {ly['header_len']} bytes de cabeçalho "
                         f"(offset {ly['offset']})", expanded=i < 3):
            st.dataframe(pd.DataFrame(ly["fields"]), hide_index=True)
    with st.expander("Bytes brutos (hexdump)"):
        st.code(packet_view.hex_dump(pkt), language=None)

# --------------------------------------------------------------------------- #
# 4. Protocolos
# --------------------------------------------------------------------------- #
with tabs[3]:
    sub = st.tabs(["DNS", "TCP", "HTTP", "TLS", "ARP / ICMP"])

    with sub[0]:
        tx = protocols.dns_transactions(df)
        if tx.empty:
            st.info("Nenhum pacote DNS nos dados filtrados.")
        else:
            s = protocols.dns_summary(tx)
            c = st.columns(5)
            c[0].metric("Consultas", s["consultas"])
            c[1].metric("Respondidas", s["respondidas"])
            c[2].metric("Sem resposta", s["sem_resposta"])
            c[3].metric("NXDOMAIN", s["nxdomain"])
            c[4].metric("Tempo médio de resposta", f"{s['tempo_medio_ms']:.1f} ms" if s["tempo_medio_ms"] else "—")
            col1, col2 = st.columns(2)
            top = tx["nome"].value_counts().head(15).rename_axis("nome").reset_index(name="consultas")
            col1.plotly_chart(px.bar(top.sort_values("consultas"), x="consultas", y="nome", orientation="h",
                                     title="Domínios mais consultados"))
            col2.plotly_chart(px.pie(tx, names="tipo", title="Tipos de registro consultados", hole=0.4))
            st.dataframe(tx, hide_index=True)
            download(tx, "dns.csv", key="dl_dns_tab")

    with sub[1]:
        sess = protocols.tcp_sessions(df)
        if sess.empty:
            st.info("Nenhum pacote TCP nos dados filtrados.")
        else:
            c = st.columns(4)
            c[0].metric("Conexões (fluxos)", len(sess))
            c[1].metric("Handshakes completos", int((sess["handshake"] == "Completo").sum()))
            c[2].metric("Apenas SYN (sem resposta)", int((sess["handshake"] == "Apenas SYN").sum()))
            rtt = sess["rtt_handshake_ms"].dropna()
            c[3].metric("RTT médio do handshake", f"{rtt.mean():.2f} ms" if len(rtt) else "—")
            col1, col2 = st.columns(2)
            col1.plotly_chart(px.bar(protocols.tcp_flag_counts(df), x="flag", y="pacotes",
                                     title="Pacotes por flag TCP"))
            col2.plotly_chart(px.pie(sess, names="handshake", title="Estado do three-way handshake", hole=0.4))
            st.caption("**Three-way handshake:** cliente envia SYN → servidor responde SYN-ACK → cliente confirma "
                       "com ACK. O RTT do handshake é o tempo entre o SYN e o SYN-ACK.")
            st.dataframe(sess, hide_index=True)
            download(sess, "tcp_conexoes.csv", key="dl_tcp_tab")

    with sub[2]:
        http = protocols.http_messages(df)
        if http.empty:
            st.info("Nenhuma mensagem HTTP em texto claro (HTTP/1.x) nos dados filtrados. "
                    "Tráfego HTTPS aparece na aba TLS.")
        else:
            req = http[http["http_type"] == "request"]
            resp = http[http["http_type"] == "response"]
            c = st.columns(3)
            c[0].metric("Requisições", len(req))
            c[1].metric("Respostas", len(resp))
            c[2].metric("Hosts distintos", req["http_host"].nunique())
            col1, col2 = st.columns(2)
            if not req.empty:
                col1.plotly_chart(px.histogram(req, x="http_method", title="Métodos HTTP"))
            if not resp.empty:
                col2.plotly_chart(px.histogram(resp, x="http_status", title="Códigos de status"))
            st.dataframe(http, hide_index=True)
            download(http, "http.csv", key="dl_http_tab")

    with sub[3]:
        hs = protocols.tls_handshakes(df)
        if hs.empty:
            st.info("Nenhum handshake TLS (ClientHello/ServerHello) nos dados filtrados.")
        else:
            srv = protocols.tls_servers(df)
            c = st.columns(3)
            c[0].metric("ClientHello", int((hs["tls_handshake"] == "ClientHello").sum()))
            c[1].metric("ServerHello", int((hs["tls_handshake"] == "ServerHello").sum()))
            c[2].metric("Servidores (SNI)", srv["sni"].nunique())
            st.caption("O **SNI** (Server Name Indication) é enviado em texto claro no ClientHello e revela o nome "
                       "do servidor acessado, mesmo com o conteúdo cifrado.")
            st.markdown("**Servidores acessados**")
            st.dataframe(srv, hide_index=True)
            st.markdown("**Mensagens de handshake**")
            st.dataframe(hs, hide_index=True)
            download(hs, "tls.csv", key="dl_tls_tab")

    with sub[4]:
        arp = df[df["protocol"] == "ARP"]
        icmp = df[df["transport"].isin(["ICMP", "ICMPv6"])]
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**ARP** · {len(arp)} pacotes")
            if not arp.empty:
                st.dataframe(arp[["no", "rel_time", "src_mac", "src_ip", "dst_ip", "info"]], hide_index=True)
        with col2:
            st.markdown(f"**ICMP** · {len(icmp)} pacotes")
            if not icmp.empty:
                st.dataframe(icmp[["no", "rel_time", "src_ip", "dst_ip", "info"]], hide_index=True)

# --------------------------------------------------------------------------- #
# 5. Anomalias
# --------------------------------------------------------------------------- #
with tabs[4]:
    st.caption("As ocorrências abaixo são **indícios** obtidos por regras e limiares configuráveis — não "
               "confirmam a existência de ataques. Ajuste os limiares ao perfil da rede analisada.")
    with st.expander("Limiares de detecção", icon=":material/tune:"):
        d = anomalies.Thresholds()
        c = st.columns(5)
        th = anomalies.Thresholds(
            window_s=c[0].number_input("Janela (s)", 0.1, 3600.0, d.window_s),
            scan_ports=c[1].number_input("Portas p/ varredura", 2, 65535, d.scan_ports),
            scan_hosts=c[2].number_input("Hosts p/ varredura horizontal", 2, 100000, d.scan_hosts),
            syn_count=c[3].number_input("SYNs por destino", 1, 10 ** 7, d.syn_count),
            syn_ratio=c[4].number_input("Razão SYN/SYN-ACK", 1.0, 1000.0, d.syn_ratio),
            dns_rate=c[0].number_input("Consultas DNS por origem", 1, 10 ** 6, d.dns_rate),
            dns_name_len=c[1].number_input("Tamanho de nome DNS longo", 10, 253, d.dns_name_len),
            dns_entropy=c[2].number_input("Entropia de subdomínio", 1.0, 6.0, d.dns_entropy, step=0.1),
            dns_nxdomain=c[3].number_input("Respostas NXDOMAIN", 1, 10 ** 6, d.dns_nxdomain),
            icmp_rate=c[4].number_input("Pacotes ICMP por origem", 1, 10 ** 7, d.icmp_rate),
        )
    an = anomalies.detect_all(df, th)
    if an.empty:
        st.success("Nenhum comportamento anômalo identificado com os limiares atuais.")
    else:
        counts = an["severidade"].value_counts()
        c = st.columns(4)
        c[0].metric("Ocorrências", len(an))
        c[1].metric("Alta", int(counts.get("Alta", 0)))
        c[2].metric("Média", int(counts.get("Média", 0)))
        c[3].metric("Baixa", int(counts.get("Baixa", 0)))

        # Linha do tempo: tráfego total + faixas das anomalias
        tl = stats.timeline(df, stats.auto_bucket(summ["duration"]), by_protocol=False)
        fig = go.Figure()
        fig.add_scatter(x=tl["t"], y=tl["pacotes"], mode="lines", name="pacotes", line_color="#202020")
        for _, a in an.iterrows():
            fig.add_vrect(x0=a["inicio_s"], x1=max(a["fim_s"], a["inicio_s"] + 0.05), opacity=0.2, line_width=0,
                          fillcolor=SEV_COLORS[a["severidade"]])
        fig.update_layout(title="Tráfego e períodos com anomalias", xaxis_title="tempo (s)", yaxis_title="pacotes",
                          height=300)
        st.plotly_chart(fig)

        for _, a in an.iterrows():
            with st.expander(f"{a['severidade']} · {a['tipo']} — origem {a['origem']} → {a['alvo']}"):
                st.markdown(f"**Evidência:** {a['evidencia']}")
                st.markdown(f"**Período:** {a['inicio_s']:.3f}s – {a['fim_s']:.3f}s")
                st.markdown(f"**Interpretação:** {a['descricao']}")
        st.dataframe(an, hide_index=True)
        download(an, "anomalias.csv", key="dl_anom_tab")

# --------------------------------------------------------------------------- #
# 6. Exportação
# --------------------------------------------------------------------------- #
with tabs[5]:
    st.markdown("Exporte os resultados (considerando os filtros ativos) em CSV, compatível com Excel e pandas.")
    tables = {
        "pacotes.csv": df.drop(columns=["timestamp"], errors="ignore"),
        "protocolos.csv": stats.protocol_distribution(df),
        "top_ips.csv": stats.top_ips(df, 1000),
        "top_portas.csv": stats.top_ports(df, 1000),
        "conversas.csv": stats.conversations(df, 10 ** 6),
        "serie_temporal.csv": stats.timeline(df),
        "dns.csv": protocols.dns_transactions(df),
        "tcp_conexoes.csv": protocols.tcp_sessions(df),
        "http.csv": protocols.http_messages(df),
        "tls.csv": protocols.tls_handshakes(df),
        "anomalias.csv": anomalies.detect_all(df, th),
    }
    cols = st.columns(3)
    for i, (name, t) in enumerate(tables.items()):
        with cols[i % 3]:
            st.download_button(f"⬇{name} ({len(t)} linhas)", csv_bytes(t), file_name=name, mime="text/csv",
                               key=f"exp_{name}", disabled=t.empty, icon=":material/download:")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, t in tables.items():
            if not t.empty:
                z.writestr(name, csv_bytes(t))
    st.download_button("Baixar tudo (.zip)", zbuf.getvalue(), file_name="netscope_relatorio.zip",
                       mime="application/zip", type="primary", icon=":material/folder_zip:")
