# NetScope: Sistema de Análise de Rede

Aplicação acadêmica para **análise e visualização de tráfego de redes** a partir de arquivos PCAP/PCAPNG,
com inspeção de pacotes camada a camada e identificação de comportamentos anômalos.

Projeto da disciplina de Redes de Computadores. Bacharelado em Ciência da Computação, Centro de Informática, UFPB.

**Sumário**

1. [Funcionalidades](#funcionalidades)
2. [Instalação](#instalação)
3. [Execução](#execução)
4. [Guia rápido: tour de 5 minutos](#guia-rápido-tour-de-5-minutos)
5. [Guia da interface](#guia-da-interface)
6. [Analisando suas próprias capturas](#analisando-suas-próprias-capturas)
7. [Como funciona](#como-funciona)
8. [Regras de anomalia](#regras-de-anomalia)
9. [Arquivos exportados](#arquivos-exportados)
10. [Uso como biblioteca Python](#uso-como-biblioteca-python)
11. [Validação](#validação)
12. [Estrutura do projeto](#estrutura-do-projeto)
13. [Conceitos de redes usados](#conceitos-de-redes-usados)
14. [Limitações](#limitações)
15. [Solução de problemas](#solução-de-problemas)

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

Requer **Python 3.10 ou mais recente**. As dependências estão em `requirements.txt`: Scapy, pandas,
Streamlit, Plotly e pytest.

**Linux / macOS**

```bash
git clone git@github.com:larissagondim/netscope.git
cd netscope
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/larissagondim/netscope.git
cd netscope
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Para conferir se a instalação está correta, rode os testes. Todos devem passar:

```bash
python -m pytest -q
```

## Execução

```bash
streamlit run app.py
```

O navegador abre em `http://localhost:8501`. Se não abrir sozinho, acesse o endereço manualmente.

Opções úteis do Streamlit:

| Opção | Para quê |
|---|---|
| `--server.port 8600` | usar outra porta, se a 8501 estiver ocupada |
| `--server.maxUploadSize 1000` | aceitar uploads de até 1000 MB (o padrão é 200 MB) |
| `--server.headless true` | não abrir o navegador automaticamente (útil em servidor/SSH) |

Exemplo: `streamlit run app.py --server.maxUploadSize 1000`

## Guia rápido: tour de 5 minutos

O repositório traz um PCAP sintético, `exemplos/exemplo_netscope.pcap`, com tráfego normal (ARP, ICMP, DNS,
HTTP, TLS) e **ataques plantados** (varredura, SYN flood, tunelamento DNS, NXDOMAIN e ARP spoofing). Ele é o
melhor ponto de partida para conhecer a ferramenta.

1. **Abra o exemplo.** Na barra lateral, em *Fonte dos dados*, escolha **Exemplo incluído**. Na tela inicial,
   o botão **Abrir exemplo** faz o mesmo. O topo mostra 1.225 pacotes em cerca de 20 s.
2. **Visão geral.** O gráfico de rosca mostra que TCP domina (≈ 78% dos pacotes) e DNS vem em seguida
   (≈ 15%). No gráfico *Tráfego ao longo do tempo* aparece um pico perto de t = 10 s: é o SYN flood.
   O cartão *Hosts (IPs)* mostra 408 hosts. Quase todos são origens falsificadas do flood.
3. **Pacotes.** É a lista no estilo do Wireshark. Digite `GET` em *Buscar no campo Info* na barra lateral
   para ver só as requisições HTTP, e clique em uma linha para selecioná-la. Apague o filtro ao terminar.
4. **Inspeção.** Abra o pacote **14** (uma requisição HTTP). A barra de encapsulamento mostra os cabeçalhos
   **Ethernet (14 B) → IP (20 B) → TCP (20 B)** e os dados HTTP começando no byte 54. Abra os painéis de cada
   camada para ver os campos, e o *hexdump* para ver os bytes brutos.
5. **Protocolos.**
   - *DNS*: 93 consultas, todas respondidas, 15 NXDOMAIN e tempo médio de resposta de ≈ 18 ms.
   - *TCP*: 621 fluxos, sendo 18 handshakes completos (RTT de 8, 12 e 30 ms) e 600 com apenas SYN (o flood
     e a varredura).
   - *HTTP*: 6 GET para `example.com/index.html`, todos com resposta 200.
   - *TLS*: 12 ClientHello com SNI `www.google.com` e `ufpb.br`, negociando TLS 1.3, 6 conexões para cada.
6. **Anomalias.** Seis ocorrências:

   | Severidade | Tipo | Origem → alvo |
   |---|---|---|
   | Alta | Varredura de portas | 192.168.0.66 → 192.168.0.11 (200 portas em ≈ 2 s) |
   | Alta | Excesso de SYN | 401 origens distintas → 93.184.216.34 |
   | Alta | Conflito ARP | 2 MACs para o IP 192.168.0.1 |
   | Média | Volume elevado de consultas DNS | 192.168.0.10 |
   | Média | Nomes DNS incomuns | 192.168.0.10 → `exfil-data.net` |
   | Baixa | Muitas respostas NXDOMAIN | 192.168.0.11 |

   Abra *Limiares de detecção* e aumente *Respostas NXDOMAIN* para 20: a ocorrência de NXDOMAIN some, porque o
   cliente recebeu 15. É assim que se ajusta a ferramenta ao perfil de uma rede.

   Os limiares interagem entre si. Se você subir *Portas p/ varredura* acima de 200, a varredura não some:
   ela reaparece como **Excesso de SYN**, porque continua sendo uma rajada de SYNs sem resposta.
7. **Exportar.** Baixe `anomalias.csv` ou **Baixar tudo (.zip)** e abra no Excel ou no pandas.

## Guia da interface

### Barra lateral

**Captura**

| Controle | O que faz |
|---|---|
| *Fonte dos dados* | **Arquivo PCAP** (upload de `.pcap`, `.pcapng` ou `.cap`), **Exemplo incluído** ou **Captura ao vivo** |
| *Limite de pacotes* | lê só os N primeiros pacotes (0 = todos). Útil para capturas grandes |

**Filtros.** Valem para **todas as abas**, inclusive anomalias e exportação.

| Filtro | Como funciona |
|---|---|
| *Protocolos* | mostra só os protocolos escolhidos (vazio = todos) |
| *Endereço IP* | pacotes em que o IP é origem **ou** destino. É preciso digitar o endereço exato, como `192.168.0.10` |
| *Porta* | pacotes em que a porta é origem **ou** destino |
| *Intervalo de tempo* | recorte em segundos, contados a partir do primeiro pacote |
| *Buscar no campo Info* | texto contido na coluna *Info*, sem diferenciar maiúsculas (ex.: `SYN`, `GET`, `NXDOMAIN`) |

O cabeçalho da página mostra o nome da captura e quantos pacotes passaram pelos filtros (ex.: "120 de 1,225
pacotes"). Logo abaixo ficam os cartões de **pacotes, bytes, duração, taxa média, pacotes/s e hosts**.

### Visão geral

- **Distribuição de protocolos** por pacotes ou por bytes. Cada pacote conta no protocolo de mais alto nível
  reconhecido. Um pacote DNS, por exemplo, conta como DNS e não como UDP.
- **Tráfego ao longo do tempo**, empilhado por protocolo. O tamanho do intervalo é escolhido automaticamente
  para gerar no máximo cerca de 200 pontos.
- **Top 10 endereços IP** (enviados × recebidos) e **Top 10 portas de destino**, com o nome do serviço
  conhecido (443 = HTTPS, 53 = DNS…).
- **Tamanho dos pacotes** por faixa e **protocolos de transporte**.
- **Conversas entre hosts**: pares de IP sem direção, com pacotes, bytes, duração e protocolos.

### Pacotes

Tabela com Nº, tempo, origem, destino, portas, protocolo, tamanho e *Info*. Clique em uma linha para
selecioná-la. Ao abrir a aba **Inspeção**, esse pacote já vem carregado. O botão abaixo da tabela exporta os
pacotes filtrados em CSV.

### Inspeção

Mostra como um quadro é montado por **encapsulamento**:

1. **Barra de encapsulamento**: um segmento por cabeçalho, proporcional ao tamanho em bytes. Passe o mouse
   para ver o intervalo de bytes ocupado.
2. **Pilha de protocolos**: cada camada com sua posição no modelo TCP/IP (Enlace, Rede, Transporte,
   Aplicação), o tamanho do cabeçalho e o offset no quadro.
3. **Campos dos cabeçalhos**: todos os campos de cada camada, como no painel de detalhes do Wireshark.
4. **Hexdump**: os bytes brutos do quadro.

O número do pacote se refere à captura completa, o mesmo Nº da aba *Pacotes*.

### Protocolos

| Sub-aba | Conteúdo |
|---|---|
| **DNS** | cada consulta pareada com a resposta (mesmo ID, cliente, servidor e porta), com o status (NOERROR, NXDOMAIN…), as respostas e o tempo de resposta. Mostra também os domínios mais consultados e os tipos de registro |
| **TCP** | uma linha por conexão, com o estado do three-way handshake, o RTT do handshake, o encerramento (FIN, RST ou aberta), pacotes, bytes e duração. Inclui a contagem de pacotes por flag |
| **HTTP** | requisições e respostas HTTP/1.x em texto claro: método, host, URI, status, User-Agent |
| **TLS** | servidores acessados (SNI) com a versão negociada, e a lista de ClientHello/ServerHello |
| **ARP / ICMP** | pacotes ARP (quem pergunta e quem responde) e mensagens ICMP |

### Anomalias

- **Limiares de detecção**: dez parâmetros ajustáveis. Os resultados são recalculados na hora. Veja a
  [tabela de regras](#regras-de-anomalia).
- Cartões com o total de ocorrências por severidade (**Alta**, **Média**, **Baixa**).
- **Tráfego e períodos com anomalias**: a curva de pacotes com faixas sombreadas nos períodos suspeitos.
- Um painel por ocorrência com a **evidência** (números que dispararam a regra), o **período** e a
  **interpretação**.

As ocorrências são **indícios**, não confirmação de ataque.

### Exportar

Um botão para cada tabela e **Baixar tudo (.zip)**. Os arquivos respeitam os filtros ativos. Veja
[Arquivos exportados](#arquivos-exportados).

## Analisando suas próprias capturas

> Capture apenas tráfego de redes e equipamentos que são seus ou que você tem autorização para analisar.

**Com o Wireshark:** escolha a interface, capture o tráfego e use *File → Save As* em formato `pcapng` ou `pcap`.
Depois envie o arquivo em **Arquivo PCAP**.

**Com o tcpdump (Linux/macOS):**

```bash
sudo tcpdump -i eth0 -w minha_captura.pcap             # uma interface (veja os nomes com: ip link)
sudo tcpdump -i any -w tudo.pcap                       # todas as interfaces (formato Linux cooked, suportado)
sudo tcpdump -i eth0 -w web.pcap 'port 53 or port 80 or port 443'   # só DNS e web
```

Pare com `Ctrl+C`.

**Captura ao vivo pelo próprio NetScope.** Exige privilégios para abrir a interface em modo de captura:

```bash
sudo .venv/bin/streamlit run app.py      # Linux/macOS: use o streamlit do venv, não o do sistema
```

No Windows, instale o [Npcap](https://npcap.com) e abra o terminal como Administrador. Na barra lateral,
escolha a interface, o número de pacotes, o tempo máximo e, se quiser, um filtro BPF (ex.: `tcp port 443`).
Depois clique em **Iniciar captura**. O botão **Salvar captura (.pcap)** guarda o resultado para abrir
depois no Wireshark.

Nesse modo, a aplicação web inteira roda como administrador. Sempre que possível, prefira capturar com o
Wireshark ou o tcpdump e enviar o arquivo.

## Como funciona

```
PCAP ──► parser.py ──► DataFrame (1 linha por pacote) ──┬──► stats.py      (visão geral)
          (Scapy)       + bytes brutos de cada quadro    ├──► protocols.py  (DNS, TCP, HTTP, TLS)
                                    │                    ├──► anomalies.py  (regras)
                                    └──► packet_view.py  └──► app.py        (interface, CSV)
                                         (inspeção)
```

1. **Leitura**: `PcapReader` (Scapy) percorre o arquivo pacote a pacote. Cada pacote vira um dicionário de
   campos (MACs, IPs, portas, flags TCP, campos DNS/HTTP/TLS), e o conjunto forma um `DataFrame` do pandas.
   Os bytes brutos são guardados para reconstruir o pacote na inspeção. Um pacote malformado vira uma linha
   "Malformado" e não interrompe a leitura.
2. **Classificação**: cada pacote recebe o protocolo de mais alto nível reconhecido
   (ARP → ICMP → TCP/UDP → DNS/HTTP/TLS).
   - Mensagens no formato DNS nas portas 5353 e 5355 são rotuladas **MDNS** e **LLMNR**, como no Wireshark,
     e ficam fora das análises e anomalias de DNS.
   - **HTTP** é reconhecido pela linha inicial (`GET …`, `HTTP/1.1 …`), em qualquer porta.
   - **TLS** é reconhecido pelo cabeçalho de registro (tipo 20–23, versão `0x03xx`). O ClientHello é
     interpretado manualmente para extrair o **SNI** e a versão anunciada na extensão `supported_versions`,
     o que identifica o TLS 1.3.
3. **Encapsulamento**: na inspeção, o pacote é percorrido camada por camada (`layer.payload`). Para cada camada
   são calculados o tamanho do cabeçalho (`len(camada) − len(payload)`) e o offset no quadro.
4. **Pareamento DNS**: cada consulta é ligada à primeira resposta posterior com o mesmo ID, cliente, servidor e
   porta do cliente (`merge_asof`). Consultas sem par aparecem como "SEM RESPOSTA".
5. **Sessões TCP**: os pacotes são agrupados pela 4-tupla (IPs e portas). Se a mesma 4-tupla for reutilizada,
   um SYN novo abre outra sessão quando a anterior terminou (FIN/RST), quando o número de sequência inicial
   (ISN) é diferente, ou quando a sessão anterior foi capturada já em andamento. Um SYN retransmitido (mesmo
   ISN) continua na mesma sessão. O RTT do handshake é o tempo entre o SYN e o SYN-ACK.
6. **TLS**: cada ClientHello é ligado ao primeiro ServerHello seguinte na mesma 4-tupla, para obter a versão
   negociada.
7. **Anomalias**: regras sobre uma **janela deslizante** de tempo, explicadas na próxima seção.

## Regras de anomalia

Todos os limiares são ajustáveis em *Anomalias → Limiares de detecção*. Os valores abaixo são os padrões.

| Regra | Critério padrão | Parâmetros na interface |
|---|---|---|
| Varredura de portas | ≥ 20 portas distintas de um mesmo destino, vindas da mesma origem, em 10 s (SYN sem ACK ou UDP) | *Janela*, *Portas p/ varredura* |
| Varredura de hosts | ≥ 15 hosts distintos na mesma porta, vindos da mesma origem, em 10 s | *Hosts p/ varredura horizontal* |
| Excesso de SYN | ≥ 100 SYN para um destino em 10 s **e** razão SYN/SYN-ACK ≥ 3 | *SYNs por destino*, *Razão SYN/SYN-ACK* |
| Volume de DNS | ≥ 50 consultas de uma origem em 10 s | *Consultas DNS por origem* |
| Nomes DNS incomuns | nome com ≥ 50 caracteres, ou subdomínio com ≥ 12 caracteres e entropia ≥ 3,8 bits/caractere | *Tamanho de nome DNS longo*, *Entropia de subdomínio* |
| NXDOMAIN | ≥ 10 respostas de domínio inexistente para um cliente | *Respostas NXDOMAIN* |
| Conflito ARP | um mesmo IP anunciado por mais de um MAC | — |
| ICMP | ≥ 100 pacotes ICMP de uma origem para um destino em 10 s | *Pacotes ICMP por origem* |

**Janela deslizante.** Uma ocorrência é detectada se *qualquer* intervalo de 10 s atingir o limiar, e não só
intervalos alinhados em 0, 10, 20 s. Com janelas fixas, uma varredura de 30 portas que começa em t = 9,5 s seria
dividida em 15 + 15 e não seria detectada. Janelas sobrepostas que disparam são unidas em um único episódio,
e cada evento aparece uma vez. A evidência informa o **pico**: o maior valor observado dentro de uma janela.

**Severidade.** Varredura de portas é *Alta* quando atinge três vezes o limiar e *Média* abaixo disso.
Excesso de SYN e conflito ARP são sempre *Alta*. Nomes DNS incomuns são *Média* com 5 ou mais consultas e
*Baixa* abaixo disso. NXDOMAIN é *Baixa*.

**Falsos positivos conhecidos.** Conflitos ARP também aparecem com VRRP/HSRP (roteadores redundantes) e com IPs
reatribuídos pelo DHCP. Nomes longos aparecem em CDNs e serviços de telemetria. `traceroute` em UDP pode parecer
uma varredura de portas.

## Arquivos exportados

Todos em CSV UTF-8 com BOM (abrem com acentos corretos no Excel), respeitando os filtros ativos.

| Arquivo | Conteúdo |
|---|---|
| `pacotes.csv` | uma linha por pacote, com todos os campos extraídos (veja abaixo) |
| `protocolos.csv` | pacotes, bytes e percentuais por protocolo |
| `top_ips.csv` | pacotes e bytes enviados/recebidos por IP |
| `top_portas.csv` | portas de destino por transporte, com o nome do serviço |
| `conversas.csv` | pares de hosts: pacotes, bytes, início, fim, duração e protocolos |
| `serie_temporal.csv` | pacotes, bytes, pps e bps por intervalo de tempo e protocolo |
| `dns.csv` | transações DNS: nome, tipo, status, respostas, tempo de resposta |
| `tcp_conexoes.csv` | conexões TCP: handshake, RTT, encerramento, pacotes, bytes, duração |
| `http.csv` | mensagens HTTP: método, host, URI, status, User-Agent, Content-Type |
| `tls.csv` | ClientHello/ServerHello: versão, SNI |
| `anomalias.csv` | severidade, tipo, origem, alvo, início, fim, evidência, descrição |

**Colunas de `pacotes.csv`**

| Grupo | Colunas |
|---|---|
| Geral | `no`, `time` (epoch), `rel_time` (s desde o 1º pacote), `length`, `protocol`, `info` |
| Enlace | `src_mac`, `dst_mac` |
| Rede | `src_ip`, `dst_ip`, `ip_version`, `ttl` (hop limit no IPv6) |
| Transporte | `transport`, `src_port`, `dst_port`, `tcp_flags`, `tcp_seq`, `tcp_ack`, `tcp_window`, `payload_len` |
| ARP / ICMP | `arp_op`, `arp_hwsrc`, `icmp_type`, `icmp_code` |
| DNS / mDNS / LLMNR | `dns_id`, `dns_is_response`, `dns_rcode`, `dns_qname`, `dns_qtype`, `dns_answers` |
| HTTP | `http_type`, `http_method`, `http_host`, `http_uri`, `http_status`, `http_reason`, `http_user_agent`, `http_content_type` |
| TLS | `tls_content_type`, `tls_record_version`, `tls_handshake`, `tls_version`, `tls_sni` |

As colunas de um protocolo só aparecem se ele estiver presente na captura.

## Uso como biblioteca Python

Os módulos funcionam sem a interface, o que é útil em notebooks e scripts:

```python
from netscope.parser import load_pcap, rebuild_packet
from netscope import stats, protocols, anomalies, packet_view

cap = load_pcap("exemplos/exemplo_netscope.pcap")   # caminho, bytes ou arquivo aberto
df = cap.df                                          # DataFrame com 1 linha por pacote

print(stats.summary(df))                  # pacotes, bytes, duração, pps, bps, hosts…
print(stats.protocol_distribution(df))
print(protocols.dns_summary(protocols.dns_transactions(df)))
print(protocols.tcp_sessions(df).head())

th = anomalies.Thresholds(scan_ports=10, window_s=5)  # limiares personalizados
print(anomalies.detect_all(df, th)[["severidade", "tipo", "origem", "alvo"]])

for camada in packet_view.layers(rebuild_packet(cap, 13)):   # pacote nº 14 (índice 0-based)
    print(camada["name"], camada["model"], camada["header_len"], "bytes")
```

## Validação

### Testes automatizados

```bash
python -m pytest -q
```

Os testes geram o PCAP sintético e verificam contagens por protocolo, o pareamento DNS, os handshakes TCP, HTTP,
TLS, a detecção de cada anomalia e a ausência de falsos positivos em tráfego normal. Também cobrem casos de
borda: varredura que cruza a fronteira de uma janela fixa, mDNS/LLMNR, reuso de portas TCP, retransmissão de
SYN, VLAN (802.1Q) e capturas Linux cooked (`tcpdump -i any`).

O PCAP de exemplo pode ser recriado com `python scripts/gerar_pcap_exemplo.py exemplos/exemplo_netscope.pcap`.

### Comparação com o Wireshark

Requer o `tshark`, que vem com o Wireshark (no Linux: `sudo apt install tshark`).

```bash
python scripts/comparar_wireshark.py exemplos/exemplo_netscope.pcap
python scripts/comparar_wireshark.py minha_captura.pcap
```

O script conta pacotes no NetScope e aplica o filtro de exibição equivalente no `tshark`. Resultado com o PCAP
de exemplo (todas as métricas conferem):

```
Métrica                 NetScope  Wireshark  Resultado
Total de pacotes            1225       1225  OK
TCP                          986        986  OK
UDP                          186        186  OK
ICMP                          36         36  OK
ARP                           17         17  OK
DNS                          186        186  OK
MDNS                           0          0  OK
LLMNR                          0          0  OK
Consultas DNS                 93         93  OK
Requisições HTTP               6          6  OK
Respostas HTTP                 6          6  OK
TLS ClientHello               12         12  OK
TLS ServerHello               12         12  OK
TCP SYN (sem ACK)            618        618  OK
TCP RST                      206        206  OK
```

Como o PCAP de exemplo foi gerado pelo próprio projeto, a validação é mais forte com **capturas reais**.
Rode o script nas capturas dos experimentos abaixo.

### Experimentos controlados sugeridos

Use uma rede ou VM sua, nunca redes de terceiros.

| Cenário | Como gerar | Resultado esperado no NetScope |
|---|---|---|
| Navegação normal | capture com o Wireshark enquanto acessa sites | DNS + TLS com SNI, nenhuma anomalia |
| HTTP em texto claro | `python -m http.server 8080` e `curl localhost:8080` | requisição GET e resposta 200 na aba HTTP |
| Varredura | `nmap -sS <ip-da-sua-VM>` | "Varredura de portas" |
| Excesso de SYN | `hping3 -S --flood -p 80 <ip-da-sua-VM>` (por poucos segundos) | "Excesso de SYN" |
| Ping | `ping -f <ip>` (Linux, root) | "Volume elevado de ICMP" |
| Domínios inexistentes | `for i in $(seq 20); do dig nao-existe-$i.example; done` | "Muitas respostas NXDOMAIN" |

## Estrutura do projeto

```
netscope/
├── app.py                      # interface Streamlit
├── netscope/
│   ├── parser.py               # leitura do PCAP → DataFrame (1 linha por pacote)
│   ├── packet_view.py          # camadas, campos, offsets e hexdump de um pacote
│   ├── stats.py                # estatísticas gerais
│   ├── protocols.py            # DNS, TCP, HTTP, TLS
│   ├── anomalies.py            # regras de detecção, janela deslizante e limiares
│   └── capture.py              # captura ao vivo (Scapy sniff)
├── scripts/
│   ├── gerar_pcap_exemplo.py   # gera o PCAP de teste
│   └── comparar_wireshark.py   # validação com tshark
├── assets/                     # ícone e CSS da interface
├── .streamlit/config.toml      # tema da interface
├── exemplos/exemplo_netscope.pcap
└── tests/test_netscope.py      # testes automatizados (pytest)
```

## Conceitos de redes usados

| Conceito | Onde aparece | Resumo |
|---|---|---|
| Encapsulamento | Inspeção | cada camada acrescenta seu cabeçalho aos dados da camada de cima: Ethernet ⟶ IP ⟶ TCP/UDP ⟶ aplicação |
| Three-way handshake | Protocolos → TCP | abertura de conexão TCP: SYN → SYN-ACK → ACK |
| RTT | Protocolos → TCP | tempo de ida e volta. Aqui é medido entre o SYN e o SYN-ACK |
| FIN / RST | Protocolos → TCP | encerramento ordenado (FIN dos dois lados) ou abrupto (RST) |
| 4-tupla | sessões TCP | IP e porta de origem + IP e porta de destino: identificam uma conexão |
| NXDOMAIN | Protocolos → DNS | resposta DNS de "domínio inexistente" |
| SNI | Protocolos → TLS | nome do servidor, enviado **em texto claro** no ClientHello, mesmo com o conteúdo cifrado |
| SYN flood | Anomalias | muitos SYN sem concluir o handshake, enchendo a fila de conexões semiabertas do servidor |
| ARP spoofing | Anomalias | respostas ARP falsas que associam o IP de outro host (ex.: gateway) ao MAC do atacante |
| Entropia | Anomalias → DNS | mede o quão "aleatório" é um texto. Subdomínios gerados por máquina têm entropia alta |

## Limitações

- Não remonta fluxos TCP. Mensagens HTTP ou TLS divididas em vários segmentos são reconhecidas apenas pelo
  primeiro segmento, como o Wireshark faria com a remontagem desativada. Navegadores atuais enviam ClientHellos
  grandes (troca de chaves pós-quântica) que ocupam dois segmentos. Quando o SNI cai no segundo, ele não aparece.
- O NetScope reconhece HTTP em qualquer porta, mas o Wireshark só disseca como HTTP as portas registradas
  (80, 8080, 3128…). Em portas como 8000, use *Analyze → Decode As* no Wireshark antes de comparar.
- Apenas HTTP/1.x em texto claro. HTTP/2 e HTTPS aparecem como TLS. HTTP/3 (QUIC, UDP 443) aparece como UDP.
- O conteúdo cifrado do TLS não é decifrado. Só metadados do handshake são exibidos.
- A leitura processa alguns milhares de pacotes por segundo. Capturas com centenas de milhares de pacotes
  levam minutos e consomem bastante memória. Use o *Limite de pacotes*.

## Solução de problemas

| Problema | Solução |
|---|---|
| Upload recusado por passar de 200 MB | rode com `--server.maxUploadSize 1000` ou divida a captura em arquivos de 100 mil pacotes (`editcap -c 100000 grande.pcapng parte.pcapng`) |
| Leitura muito lenta | use o *Limite de pacotes* ou capture com filtro (ex.: `tcpdump … 'not port 22'`) |
| Captura ao vivo: "Permissão negada" | rode com `sudo .venv/bin/streamlit run app.py`. No Windows, como Administrador e com o Npcap instalado |
| `sudo: streamlit: command not found` | o `sudo` não enxerga o venv. Use o caminho completo `.venv/bin/streamlit` |
| "Nenhum pacote corresponde aos filtros" | limpe os filtros da barra lateral. O filtro de IP exige o endereço exato |
| `ModuleNotFoundError: scapy` (ou outro) | ative o venv (`source .venv/bin/activate`) antes de rodar |
| Porta 8501 ocupada | `streamlit run app.py --server.port 8600` |
| Contagens diferentes do Wireshark | veja as [Limitações](#limitações): remontagem TCP, HTTP em porta não padrão e mDNS/LLMNR |
