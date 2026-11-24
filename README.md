# NetScope: Sistema de Análise de Rede

Aplicação acadêmica para **análise e visualização de tráfego de redes** a partir de arquivos PCAP/PCAPNG,
com inspeção de pacotes camada a camada e identificação de comportamentos anômalos.

Projeto da disciplina de Redes de Computadores. Bacharelado em Ciência da Computação, Centro de Informática, UFPB.

## Funcionalidades

| Requisito do projeto | Onde está |
|---|---|
| Leitura de PCAP/PCAPNG (TCP, UDP, ICMP, ARP, DNS, mDNS, LLMNR, HTTP, TLS) | `netscope/parser.py` |
| Estatísticas: pacotes, bytes, protocolos, IPs, portas, evolução temporal | `netscope/stats.py`, aba **Visão geral** |
| Inspeção individual de pacotes: cabeçalhos, campos, encapsulamento, hexdump | `netscope/packet_view.py`, aba **Inspeção** |
| DNS: consultas × respostas, tempo de resposta, NXDOMAIN | `protocols.dns_transactions` |
| TCP: three-way handshake, RTT, encerramento por FIN/RST, reuso de 4-tupla | `protocols.tcp_sessions` |
| HTTP: método, host, URI, status | `protocols.http_messages` |
| TLS: versão, ClientHello/ServerHello, SNI | `protocols.tls_handshakes` / `tls_servers` |
| Anomalias: varredura de portas/hosts, excesso de SYN, DNS incomum, NXDOMAIN, ARP spoofing, ICMP flood | `netscope/anomalies.py`, aba **Anomalias** |
| Exportação CSV (individual ou .zip com tudo) | aba **Exportar** |
| Captura em tempo real (opcional) | `netscope/capture.py`, fonte **Captura ao vivo** |
| Validação contra o Wireshark | `scripts/comparar_wireshark.py` |

## Instalação

Requer Python 3.10 ou mais recente.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Execução

```bash
streamlit run app.py
```

O navegador abre em `http://localhost:8501`. Na barra lateral, escolha:

- **Arquivo PCAP**: envie um `.pcap`/`.pcapng` (por exemplo, salvo pelo Wireshark ou pelo `tcpdump -w`).
- **Exemplo incluído**: `exemplos/exemplo_netscope.pcap`, tráfego sintético com anomalias plantadas.
- **Captura ao vivo**: precisa de privilégios. Use `sudo streamlit run app.py` no Linux/macOS. No Windows,
  instale o [Npcap](https://npcap.com) e execute como Administrador.

Os filtros da barra lateral (protocolo, IP, porta, intervalo de tempo e texto) valem para todas as abas.
Clique em uma linha da aba **Pacotes** para abri-la na aba **Inspeção**.

## Estrutura

```
netscope/
├── app.py                      # interface Streamlit
├── netscope/
│   ├── parser.py               # leitura do PCAP → DataFrame (1 linha por pacote)
│   ├── packet_view.py          # camadas, campos, offsets e hexdump de um pacote
│   ├── stats.py                # estatísticas gerais
│   ├── protocols.py            # DNS, TCP, HTTP, TLS
│   ├── anomalies.py            # regras de detecção e limiares
│   └── capture.py              # captura ao vivo (Scapy sniff)
├── scripts/
│   ├── gerar_pcap_exemplo.py   # gera o PCAP de teste
│   └── comparar_wireshark.py   # validação com tshark
├── exemplos/exemplo_netscope.pcap
└── tests/test_netscope.py      # testes automatizados (pytest)
```

## Como funciona

1. **Leitura**: `PcapReader` (Scapy) percorre o arquivo pacote a pacote, sem carregar tudo como objetos Scapy.
   Cada pacote vira um dicionário de campos (MACs, IPs, portas, flags TCP, campos DNS/HTTP/TLS) e o conjunto
   forma um `DataFrame` do pandas. Os bytes brutos são guardados para reconstruir o pacote na inspeção.
2. **Classificação**: cada pacote recebe o protocolo de mais alto nível reconhecido
   (ARP → ICMP → TCP/UDP → DNS/HTTP/TLS). Mensagens no formato DNS nas portas 5353 e 5355 são rotuladas
   **MDNS** e **LLMNR**, como no Wireshark, e ficam fora das análises e anomalias de DNS. HTTP é reconhecido pela linha inicial (`GET …`, `HTTP/1.1 …`).
   TLS é reconhecido pelo cabeçalho de registro (tipo 20–23, versão `0x03xx`). O ClientHello é interpretado
   manualmente para extrair o **SNI** e a versão anunciada na extensão `supported_versions`, o que identifica o TLS 1.3.
3. **Encapsulamento**: na inspeção, o pacote é percorrido camada por camada (`layer.payload`). Para cada camada
   são calculados o tamanho do cabeçalho (`len(camada) − len(payload)`) e o offset no quadro, e os campos
   aparecem como no painel de detalhes do Wireshark.
4. **Sessões TCP**: os pacotes são agrupados pela 4-tupla (IPs e portas). Se a mesma 4-tupla for reutilizada,
   um SYN novo abre outra sessão quando a anterior terminou (FIN/RST) ou quando o número de sequência inicial
   é diferente. Um SYN retransmitido continua na mesma sessão.
5. **Anomalias**: regras sobre uma **janela deslizante** de tempo, todas com limiares ajustáveis na interface.
   Uma ocorrência é detectada se *qualquer* intervalo de 10 s atingir o limiar, não só intervalos alinhados
   em 0, 10, 20 s. Assim, uma varredura que cruza a fronteira entre duas janelas fixas não escapa. Janelas
   sobrepostas que disparam são unidas em um único episódio.

| Regra | Critério padrão |
|---|---|
| Varredura de portas | ≥ 20 portas distintas de um mesmo destino, vindas da mesma origem, em 10 s (SYN sem ACK ou UDP) |
| Varredura de hosts | ≥ 15 hosts distintos na mesma porta, vindos da mesma origem, em 10 s |
| Excesso de SYN | ≥ 100 SYN para um destino em 10 s **e** razão SYN/SYN-ACK ≥ 3 |
| Volume de DNS | ≥ 50 consultas de uma origem em 10 s |
| Nomes DNS incomuns | nome com ≥ 50 caracteres, ou subdomínio com ≥ 12 caracteres e entropia ≥ 3,8 bits/caractere |
| NXDOMAIN | ≥ 10 respostas de domínio inexistente para um cliente |
| Conflito ARP | um mesmo IP anunciado por mais de um MAC |
| ICMP | ≥ 100 pacotes ICMP de uma origem para um destino em 10 s |

As ocorrências são **indícios**, não confirmação de ataque.

## Validação

**Testes automatizados:**

```bash
python -m pytest -q
```

**Comparação com o Wireshark** (requer `tshark`):

```bash
python scripts/comparar_wireshark.py exemplos/exemplo_netscope.pcap
```

Resultado com o PCAP de exemplo. Todas as métricas conferem:

```
Métrica                 NetScope  Wireshark  Resultado
Total de pacotes            1225       1225  OK
TCP                          986        986  OK
UDP                          186        186  OK
ICMP                          36         36  OK
ARP                           17         17  OK
DNS                          186        186  OK
Consultas DNS                 93         93  OK
Requisições HTTP               6          6  OK
Respostas HTTP                 6          6  OK
TLS ClientHello               12         12  OK
TLS ServerHello               12         12  OK
TCP SYN (sem ACK)            618        618  OK
TCP RST                      206        206  OK
```

**Experimentos controlados sugeridos** (em uma rede/VM sua, nunca em redes de terceiros):

| Cenário | Como gerar | Resultado esperado no NetScope |
|---|---|---|
| Navegação normal | capture com Wireshark enquanto acessa sites | DNS + TLS com SNI, nenhuma anomalia |
| HTTP em texto claro | `python -m http.server 8080` e `curl localhost:8080` | requisição GET e resposta 200 na aba HTTP |
| Varredura | `nmap -sS <ip-da-sua-VM>` | "Varredura de portas" |
| Excesso de SYN | `hping3 -S --flood -p 80 <ip-da-sua-VM>` (por poucos segundos) | "Excesso de SYN" |
| Ping | `ping -f <ip>` (Linux, root) | "Volume elevado de ICMP" |

## Limitações

- Não remonta fluxos TCP. Mensagens HTTP ou TLS divididas em vários segmentos são reconhecidas apenas pelo
  primeiro segmento, como o Wireshark faria com a remontagem desativada.
- O NetScope reconhece HTTP em qualquer porta, mas o Wireshark só disseca como HTTP as portas registradas
  (80, 8080, 3128…). Em portas como 8000, use *Analyze → Decode As* no Wireshark antes de comparar.
- Apenas HTTP/1.x em texto claro. HTTP/2 e HTTPS aparecem como TLS.
- O conteúdo cifrado do TLS não é decifrado. Só metadados do handshake são exibidos.
- Capturas muito grandes (centenas de MB) consomem bastante memória. Use o campo "Limite de pacotes".
