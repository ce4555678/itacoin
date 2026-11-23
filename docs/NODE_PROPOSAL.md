# Minerador, RPC e nó — aprovado

> Aprovado em 2026-11-23, com todos os pontos da seção 9, e implementado em
> `itacoin-miner`, `itacoin-rpc` (com o binário `itacoin-cli`) e
> `itacoin-node`. Fecha o item 1 dos próximos passos de
> [REMEDIATION.md](REMEDIATION.md), inclusive as proteções de processo do
> achado V-07. Nada aqui é regra de consenso. Segue a seção 3
> (representação em texto) de [PROTOCOL_REQUIREMENTS.md](PROTOCOL_REQUIREMENTS.md).
> A seção 10 registra os ajustes e o que ainda não foi implementado.

## 1. Escopo e fronteiras

| Componente | Faz | Não faz |
| --- | --- | --- |
| `itacoin-miner` (biblioteca) | monta templates, procura nonces em várias threads, descarta trabalho velho | I/O, rede, chaves |
| `itacoin-rpc` (biblioteca) | servidor JSON-RPC, autenticação, limites, conversão para texto | guardar estado próprio; tudo passa pelo `NodeHandle` |
| `itacoin-node` (binário) | configuração, diretório de dados, sinais, logs, proteções de processo, liga rede + RPC + minerador | lógica de consenso ou de rede |
| `itacoin-cli` (binário, em `itacoin-rpc`) | cliente de linha de comando do RPC | — |

**A carteira fica fora do nó.** O nó nunca carrega uma chave privada: o
minerador só precisa de um endereço de pagamento, e uma transação chega ao nó
já assinada (`sendrawtransaction`). Isso mantém a seed ML-DSA fora de um
processo exposto à rede e ao RPC, que é a proteção mais forte contra o V-07.
A carteira continua sendo `itacoin-wallet` e ganha um binário próprio numa
etapa futura, consumindo o RPC desta proposta (seção 5.4).

## 2. Modelo de ameaças

| Ameaça | Onde | Defesa principal (seção) |
| --- | --- | --- |
| **Acesso não autorizado ao RPC** | processo local de outro usuário, página web via DNS rebinding, exposição acidental na internet | escuta só em loopback, cookie com permissão 0600, checagem de `Host` e sem CORS (4.2) |
| **DoS pelo RPC** | corpo enorme, lote enorme, chamada cara repetida | limites antes de decodificar, chamadas com custo limitado, conexões limitadas (4.4) |
| **Panic remoto** | entrada inesperada num `expect` do template ou do RPC | nenhum `expect` alcançável por entrada externa; erros tipados (3.5, 4.4) |
| **Mineração desperdiçada** | minerar sobre um tip velho durante a sincronização ou após um bloco novo | geração de trabalho e espera do fim da IBD (3.3) |
| **Pagamento ao endereço errado** | endereço de outra rede ou digitado errado | Bech32m com prefixo de rede, recusado na partida (3.4) |
| **Extração de segredos locais** | core dump, `ptrace`, swap | `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0` e nenhuma chave no nó (6.4) |
| **Corrupção do estado** | duas instâncias no mesmo diretório; queda durante a escrita | trava exclusiva do diretório; `redb` já é transacional (6.2) |

**Fora de escopo.** O RPC não é uma API pública: quem quiser expô-lo a outra
máquina usa um túnel SSH ou um proxy reverso com TLS. Um usuário com acesso
ao arquivo de cookie tem controle total do nó, como no Bitcoin Core.

## 3. Minerador

### 3.1 Opções

| Opção | Para quem | Complexidade | Observação |
| --- | --- | --- | --- |
| **Minerador embutido no nó** | quem roda um nó | baixa | um processo, sem protocolo extra |
| `getblocktemplate` + `submitblock` no RPC | minerador externo, pool | média | o padrão do Bitcoin; já cai no RPC desta proposta |
| Stratum | pools com muitos mineradores | alta | protocolo e servidor próprios |

Com Argon2id de 4 MiB, um núcleo faz ≈ 330 hashes/s e uma máquina comum
alguns milhares. No lançamento, a rede é pequena e a variância de achar um
bloco é tolerável sem pool. **Proposta: minerador embutido e
`getblocktemplate`/`submitblock` no RPC; Stratum fica para quando houver
demanda.**

### 3.2 Laço de mineração

```text
thread de controle (no runtime do nó):
    a cada tip novo, ou a cada 30 s se a mempool mudou:
        template = build_block(chain, mempool, payout, agora)
        geração += 1
        publica (geração, template) para os workers

worker i de n (thread do SO, fora do tokio):
    header = template.header
    nonce  = i, i + n, i + 2n, ...
    a cada 64 tentativas:
        se geração mudou: pega o template novo
        se passaram 10 s: header.timestamp = max(agora, timestamp)
    se check_pow(header): envia o bloco por NodeHandle::submit_block
```

- **Workers fora do tokio.** O Argon2id é CPU pura e bloquearia o runtime da
  rede. Cada worker é uma `std::thread` com prioridade normal; o número
  padrão é `núcleos − 1`, para sobrar um para validação e rede.
- **Sem *extranonce*.** O nonce tem 64 bits. A 330 hashes/s por núcleo, um
  milhão de núcleos levaria ≈ 1.800 anos para esgotar o espaço de um único
  template. A coinbase não precisa de campo de dados livres, e o codec
  continua sem campos arbitrários (seção 2 do [codec](CODEC_PROPOSAL.md)).
- **Divisão do espaço de nonces** por resto (`nonce ≡ i mod n`): sem
  coordenação entre workers e sem repetir trabalho.
- **Coinbase única por altura.** `CoinbaseTransaction::new(height, ...)` já
  commita a altura, então duas coinbases de alturas diferentes nunca têm o
  mesmo txid, mesmo pagando ao mesmo endereço.
- **Template novo a cada 30 s** quando chegam transações, para não deixar
  taxas de fora. A seleção da mempool percorre até ≈ 55 mil entradas na
  thread do core, então ela não é refeita a cada transação.

### 3.3 Quando não minerar

- **Durante a sincronização inicial (IBD):** o minerador espera enquanto a
  árvore de cabeçalhos conhece uma cadeia com mais trabalho que o tip ativo,
  ou enquanto o tip tem mais de 1 hora. Minerar nesse estado é gastar
  energia num ramo que vai perder.
- **Sem peers,** fora da regtest: um bloco minerado sozinho provavelmente
  está numa partição. `--mine-without-peers` desativa essa trava para quem
  sabe o que está fazendo (por exemplo, o primeiro nó da testnet).

### 3.4 Pagamento

`--mine-address <endereço>` recebe um endereço Bech32m. O nó recusa iniciar
se o prefixo for de outra rede. A recompensa inteira (subsídio + taxas) vai
para um único output desse `wallet_id`. Para receber em vários endereços,
o minerador gasta a coinbase depois da maturidade de 100 blocos.

### 3.5 Ajustes no código atual

`itacoin-network::template` passa para `itacoin-miner`, que depende de
`itacoin-storage` e `itacoin-mempool`. `itacoin-network` usa o minerador só
como dependência de testes. Antes de servir templates pelo RPC, ele precisa
de três correções:

1. **Soma das taxas com `u64` e `+`** (`fees.sum()` e `subsidy + fees`)
   viola o requisito 2.1. Passa a usar `Amount::checked_add` e devolver erro.
2. **`expect` alcançáveis.** `build_block` passa a devolver `Result`: um
   panic causado por um estado inesperado da mempool, disparado por uma
   chamada `getblocktemplate`, derrubaria o nó.
3. **`mine` sequencial a partir de 0** fica só para testes; o laço da seção
   3.2 substitui o uso real.

### 3.6 Regtest

Na regtest a PoW é sempre válida. `generatetoaddress n endereço` monta e
submete `n` blocos na hora, sem workers, e devolve os ids. Esse método só
existe na regtest.

## 4. RPC

### 4.1 Protocolo

| Opção | Prós | Contras |
| --- | --- | --- |
| **JSON-RPC 2.0 sobre HTTP/1.1** | o que carteiras, exploradores e scripts de blockchain esperam; `curl` basta | JSON tem armadilhas com números grandes (4.3) |
| REST + JSON | URLs cacheáveis | dois estilos para manter; sem lote |
| gRPC | tipado, streaming | dependência pesada (`protobuf`, `tonic`), menos ferramentas simples |

**Proposta: JSON-RPC 2.0 sobre HTTP/1.1,** com `POST /` e lote (*batch*).
Notificações em tempo real (novo bloco, nova transação) ficam para uma
etapa futura, por WebSocket ou ZMQ.

- **Crates:** `hyper` 1.x (servidor HTTP mínimo, já sobre `tokio`),
  `serde`/`serde_json` e `base64` com `URL_SAFE_NO_PAD` (requisito 3.5),
  todas com versão fixada. O roteamento JSON-RPC é escrito à mão: são poucas
  dezenas de métodos, e `jsonrpsee` traria muito mais código do que usa.

### 4.2 Autenticação e exposição

- **Escuta só em `127.0.0.1` e `::1` por padrão.** Escutar em outro endereço
  exige `--rpc-bind` *e* `--rpc-allow-ip <rede>`; sem a segunda, o nó
  recusa iniciar.
- **Cookie:** na partida o nó gera 32 bytes aleatórios e grava
  `<datadir>/.cookie` com permissão 0600, no formato `__cookie__:<hex>`. O
  cliente usa HTTP Basic. O arquivo é apagado ao desligar. Quem lê o arquivo
  é, por definição, alguém com acesso ao diretório de dados.
- **Senha fixa opcional** (`--rpc-auth usuário:sal:hash`), para serviços em
  outra máquina. O hash é Argon2id com os parâmetros da carteira, calculado
  por `itacoin-cli rpcauth`; o nó guarda só o hash. Com 64 MiB e 3
  passagens, a verificação custa uma fração de segundo, então o resultado é
  guardado num cache por conexão.
- **Comparação em tempo constante** do segredo.
- **DNS rebinding e navegadores:** o nó recusa requisições cujo `Host` não
  seja um endereço em que escuta, não envia cabeçalhos CORS e exige
  `Content-Type: application/json`. Uma página web não consegue montar uma
  requisição aceita.
- **Falhas de autenticação:** atraso de 250 ms antes da resposta 401, e
  nenhum detalhe sobre o motivo.

### 4.3 Formato dos valores

Segue a seção 3 de PROTOCOL_REQUIREMENTS, com uma decisão a mais para
valores monetários:

| Valor | JSON | Exemplo |
| --- | --- | --- |
| Hashes, txid, block id, `wallet_id` | string, hex minúsculo | `"b97fa417…"` |
| Endereço | string, Bech32m | `"itc1…"` |
| Transação e bloco serializados | string, base64url sem padding | `"AQAA…"` |
| **Valor monetário** | **string com inteiro em satoshis**, campo com sufixo `_sat` | `"fee_sat": "5386"` |
| Altura, tempo, contagens | número | `"height": 1234` |
| Alvo e trabalho acumulado | string, hex de 64 caracteres | `"chainwork": "00…1f"` |

**Por que valores em string.** `MAX_SUPPLY` é 10^16 satoshis, acima de
2^53 ≈ 9 × 10^15, o maior inteiro que um `Number` de JavaScript representa
sem perda. Um saldo grande lido por um explorador em JavaScript seria
arredondado em silêncio. Valores decimais como `7.57229832` têm o mesmo
problema e ainda passam por ponto flutuante. Uma string com o inteiro em
satoshis não perde nada em nenhuma linguagem.

- **Entrada estrita:** a string de valor só aceita dígitos, sem sinal, sem
  zeros à esquerda e no máximo `MAX_SUPPLY`. Hex com prefixo `0x` e
  base64url com padding são recusados (requisitos 3.1 e 3.2).
- **Tamanho antes de decodificar** (requisito 3.3): uma transação em
  base64url tem no máximo ⌈4 × 100.000 / 3⌉ = 133.334 caracteres, e um bloco
  1.333.334.

### 4.4 Limites

| Limite | Valor |
| --- | --- |
| Corpo da requisição | 2 MB, verificado pelo `Content-Length` e durante a leitura |
| Itens por lote | 100 |
| Conexões simultâneas | 16; acima disso, a conexão espera na fila do `accept` |
| Tempo por requisição | 30 s |
| Profundidade do JSON | 32 níveis |
| `getblock` / `getblockheader` por lote | 10 blocos completos, 1.000 cabeçalhos |

- **O core é uma thread só.** Toda chamada vai por `NodeHandle::call` e
  roda na mesma thread que valida blocos e atende peers. Por isso uma chamada
  RPC nunca percorre algo sem limite dentro do core: listas grandes são
  paginadas, e serialização para JSON e base64 acontece fora do core, sobre
  uma cópia.
- **Erros** usam os códigos padrão do JSON-RPC (`-32700` a `-32603`) e uma
  faixa própria a partir de `-1000` (seção 5.6). Nenhuma entrada leva a
  panic; o alvo de fuzzing da seção 8 exige isso.

## 5. Métodos

### 5.1 Cadeia

| Método | Retorno |
| --- | --- |
| `getblockchaininfo` | rede, altura, tip, `chainwork`, alvo, MTP, `initial_block_download`, tamanho em disco |
| `getbestblockhash` | id do tip |
| `getblockhash altura` | id do bloco na cadeia ativa |
| `getblockheader id [formato]` | cabeçalho em JSON ou em base64url, altura, confirmações, próximo bloco |
| `getblock id [formato]` | bloco em JSON (com txids), JSON completo ou base64url |
| `getchaintips` | tips de ramos laterais conhecidos, com estado (`active`, `valid-fork`, `invalid`, `headers-only`) |
| `gettxout txid índice` | output não gasto: valor, `wallet_id`, endereço, altura, se é coinbase e se já maturou |

### 5.2 Transações e mempool

| Método | Retorno |
| --- | --- |
| `sendrawtransaction tx` | txid; erro tipado se a mempool recusar (taxa baixa, conflito, input desconhecido…) |
| `testmempoolaccept tx` | o mesmo veredito, sem adicionar nem propagar |
| `getmempoolinfo` | tamanho, bytes, taxa mínima atual, órfãs |
| `getrawmempool [após] [limite]` | txids, paginados (limite padrão 1.000) |
| `getmempoolentry txid` | taxa, tamanho, horário, ancestrais e descendentes |
| `decoderawtransaction tx` | a transação em JSON, sem tocar no estado |

**Sem `getrawtransaction` de transações confirmadas** nesta etapa: exigiria
um índice txid → bloco em disco. Fica para um índice opcional
(`--txindex`), como no Bitcoin.

### 5.3 Mineração

| Método | Retorno |
| --- | --- |
| `getblocktemplate endereço` | bloco sem PoW em base64url, alvo, altura, `prev_block`, timestamp mínimo, taxas, `template_id` |
| `submitblock bloco` | `accepted`, `duplicate`, `orphan`, `stale` ou o motivo da rejeição |
| `getmininginfo` | altura, alvo, hashes/s estimados da rede e do minerador local, workers ativos |
| `setmining ligado [threads]` | liga, desliga ou muda o número de workers |
| `generatetoaddress n endereço` | ids dos blocos (só regtest) |

O template já vem montado, com coinbase e roots: o minerador externo só varia
`nonce` e `timestamp`. Isso é mais simples que o `getblocktemplate` do
Bitcoin, que entrega as peças para o minerador montar a coinbase, e é
suficiente porque o nonce de 64 bits não se esgota (seção 3.2).

### 5.4 Endereços e carteira externa

| Método | Retorno |
| --- | --- |
| `validateaddress texto` | se é válido, rede, `wallet_id` |
| `listunspent endereços [após] [limite]` | outputs não gastos desses endereços, paginados |
| `getbalance endereços` | soma em satoshis, separando coinbase não maturada |

`listunspent` é o que uma carteira externa precisa para montar uma
transação. Hoje o UTXO set não tem índice por `wallet_id`, então a
consulta percorreria todas as moedas dentro do core. A proposta é um índice
em memória `wallet_id → outpoints`, mantido junto com o UTXO set ao aplicar e
reverter blocos. Custa ≈ 70 bytes por moeda e não entra no consenso nem no
disco: é reconstruído na partida.

**Privacidade:** esses métodos revelam ao operador do nó quais endereços
foram consultados. Como o RPC é local, o operador é o próprio usuário.

### 5.5 Rede e controle

| Método | Retorno |
| --- | --- |
| `getnetworkinfo` | versão, user agent, portas, conexões de entrada e saída, taxa mínima de relay |
| `getpeerinfo` | por peer: endereço, tipo de conexão, versão, altura, ping, bytes, tempo conectado |
| `getconnectioncount` | número de peers prontos |
| `addnode endereço add\|remove\|onetry` | conexão manual |
| `disconnectnode endereço` | desconecta |
| `listdiscouraged` / `cleardiscouraged` | IPs desencorajados por 24 h |
| `uptime` | segundos desde a partida |
| `stop` | desliga com o procedimento da seção 6.5 |

### 5.6 Códigos de erro próprios

| Código | Significado |
| --- | --- |
| `-1001` | bloco ou transação não encontrado |
| `-1002` | valor mal formatado (hex, base64url, endereço, satoshis) |
| `-1003` | endereço de outra rede |
| `-1010` | transação recusada pela mempool (com o motivo em `data`) |
| `-1011` | transação inválida por consenso |
| `-1020` | bloco recusado (com o motivo em `data`) |
| `-1030` | método indisponível nesta rede (por exemplo, `generatetoaddress` fora da regtest) |
| `-1031` | nó em sincronização inicial |

## 6. O binário `itacoin-node`

### 6.1 Configuração

- **Linha de comando** com `clap` e **arquivo opcional**
  `<datadir>/itacoin.toml` com `toml`. Precedência: linha de comando >
  arquivo > padrões da [rede](NETWORK_PROPOSAL.md).
- **`--network mainnet|testnet|regtest` é obrigatório.** Não há rede
  padrão: um comando digitado sem a rede não pode, por engano, falar com a
  mainnet ou minerar nela.
- **Opções:** `--datadir`, `--listen`, `--connect`, `--addnode`,
  `--max-inbound`, `--rpc-bind`, `--rpc-port`, `--rpc-allow-ip`,
  `--rpc-auth`, `--mine`, `--mine-address`, `--mine-threads`,
  `--mine-without-peers`, `--log-level`.
- **Portas do RPC:** 7211 na mainnet, 17211 na testnet e 17311 na regtest,
  ao lado das portas P2P.

### 6.2 Diretório de dados

```text
~/.itacoin/<rede>/
    chain.redb      estado da cadeia (já existe)
    peers.dat       tabela de endereços e âncoras (já existe)
    itacoin.toml    configuração opcional
    .cookie         segredo do RPC, 0600, apagado ao desligar
    .lock           trava exclusiva enquanto o nó roda
```

- O diretório é criado com permissão 0700.
- **Trava exclusiva** (`flock` em `.lock`): uma segunda instância no mesmo
  diretório sai com erro antes de abrir o banco.
- Na partida, `ChainStore::verify` confere o estado. Se falhar, o nó sai
  com uma mensagem que aponta `--reindex` (etapa futura) em vez de seguir com
  um estado suspeito.

### 6.3 Mainnet

A mainnet tem gênese em 2027-01-01, mas o handshake e o `ml-dsa` ainda não
passaram por revisão criptográfica independente (seções 11 e 12 da
[rede](NETWORK_PROPOSAL.md)). **Proposta: a mainnet só existe num build com
a feature `mainnet`, desligada por padrão.** O build padrão aceita testnet e
regtest; quem compila com a feature recebe um aviso na partida enquanto as
revisões estiverem pendentes.

### 6.4 Proteções de processo (V-07)

Na partida, antes de abrir qualquer arquivo:

1. `setrlimit(RLIMIT_CORE, 0)`: sem core dump;
2. `prctl(PR_SET_DUMPABLE, 0)` no Linux: bloqueia `ptrace` de processos do
   mesmo usuário e a leitura de `/proc/<pid>/mem`;
3. `umask(0o077)`: arquivos novos ficam acessíveis só ao dono.

O workspace proíbe `unsafe`, e REMEDIATION.md previa chamar a libc direto.
A proposta é usar **`rustix`**, que expõe essas chamadas com API segura
(`setrlimit`, `set_dumpable_behavior`, `umask`), em Rust puro e com versão
fixada. Assim `unsafe_code = "forbid"` continua valendo também no binário.
Em sistemas sem `prctl`, o passo 2 é pulado com um aviso.

`mlock` não é proposto para o nó, que não guarda chaves. Ele faz sentido no
futuro binário da carteira.

### 6.5 Sinais e desligamento

`SIGINT` e `SIGTERM` (e o método `stop`) disparam, nesta ordem:

1. o RPC para de aceitar conexões e termina as requisições em curso (até 5 s);
2. os workers do minerador param no próximo ponto de checagem;
3. `NodeHandle::shutdown` grava a tabela de endereços e as âncoras;
4. o banco é fechado e o `.cookie` e o `.lock` são removidos.

Um segundo sinal durante o desligamento encerra na hora. Isso é seguro
porque o `redb` é transacional: o pior caso é perder a tabela de endereços,
não o estado da cadeia.

### 6.6 Logs

Hoje a rede escreve em `stderr` com `eprintln!` quando `ITACOIN_NET_LOG`
está definida. A proposta é trocar por **`tracing`** com
`tracing-subscriber`: níveis (`error` a `trace`), filtro por módulo
(`--log-level itacoin_network=debug`) e saída em `stderr`, que o systemd e
o Docker já recolhem. Não há arquivo de log próprio nem rotação.

Os logs nunca incluem o cookie, a senha do RPC nem o corpo de requisições
RPC. IPs de peers aparecem só em `debug`.

## 7. Organização do código

| Crate | Depende de | Novas dependências |
| --- | --- | --- |
| `itacoin-miner` | `storage`, `mempool`, `consensus` | — |
| `itacoin-rpc` | `network`, `miner`, `primitives` | `hyper`, `hyper-util`, `http-body-util`, `serde`, `serde_json`, `base64` |
| `itacoin-node` | `network`, `rpc`, `miner` | `clap`, `toml`, `tracing`, `tracing-subscriber`, `rustix` |

- `itacoin-network` ganha a feature `signal` do `tokio` no binário e troca
  `eprintln!` por `tracing`.
- `itacoin-rpc` expõe uma função `serve(handle, config)`; o binário
  `itacoin-cli` mora no mesmo crate e reutiliza os tipos de requisição.
- O índice por `wallet_id` (seção 5.4) mora em `itacoin-blockchain`, ao lado
  do UTXO set, para ser atualizado na mesma operação.

## 8. Testes obrigatórios

- **Minerador:** template válido para `Chain::submit_block` com mempool
  vazia e cheia; troca de template quando chega um tip novo (nenhum bloco
  submetido sobre o tip antigo depois da troca); workers sem nonces
  repetidos; soma de taxas com overflow devolve erro em vez de panic.
- **RPC:**
  - cada método com entrada válida e com cada tipo de entrada inválida;
  - autenticação: sem cookie, cookie errado, `Host` estranho e
    `Content-Type` errado recebem recusa;
  - limites: corpo acima de 2 MB, lote de 101 itens, JSON profundo;
  - valores: ida e volta de `"10000000000000000"` sem perda; recusa de
    `"01"`, `"-1"` e de valores acima de `MAX_SUPPLY`;
  - fuzzing do parser de requisições, exigindo ausência de panic.
- **Nó:**
  - três nós em regtest iniciados pelo binário, um minerando com
    `generatetoaddress`, uma transação enviada por `sendrawtransaction` num nó
    e confirmada nos três;
  - minerador real (com PoW) numa rede de teste de dificuldade mínima,
    produzindo blocos aceitos pelos outros nós;
  - segunda instância no mesmo diretório recusada;
  - `SIGTERM` com o minerador rodando: o processo sai em menos de 10 s e
    reabre no mesmo tip;
  - `SIGKILL` durante a aplicação de um bloco: o processo reabre com o estado
    íntegro (`ChainStore::verify`).

## 9. Pontos aprovados

1. **Carteira fora do nó:** o nó nunca carrega chave privada; transações
   chegam assinadas.
2. **Minerador embutido** com workers em threads do SO (`núcleos − 1` por
   padrão), sem *extranonce*, parado durante a IBD e sem peers.
3. **`getblocktemplate` com bloco pronto** e `submitblock`; Stratum adiado.
4. **JSON-RPC 2.0 sobre HTTP** com `hyper`, roteamento escrito à mão.
5. **Autenticação por cookie**, escuta só em loopback por padrão, senha
   opcional com hash Argon2id, checagem de `Host` e sem CORS.
6. **Valores monetários como string de satoshis** (`_sat`), por causa do
   limite de 2^53 do JavaScript.
7. **Índice em memória por `wallet_id`** para `listunspent` e `getbalance`.
8. **`--network` obrigatório** e **mainnet atrás de uma feature** desligada
   por padrão até as revisões criptográficas.
9. **`rustix`** para as proteções do V-07, mantendo `unsafe` proibido.
10. **Portas do RPC** 7211 / 17211 / 17311.
11. **`clap`, `toml` e `tracing`** como dependências do binário.

## 10. Ajustes feitos na implementação

1. **A idade do tip não conta como IBD.** A regra "tip com mais de 1 hora"
   (seção 3.3) impediria o primeiro bloco de uma rede nova: a testnet tem
   só o gênese, mais antigo que isso. O nó está em IBD quando a árvore de
   cabeçalhos conhece uma cadeia com mais trabalho que o tip ou quando um
   peer pronto anunciou uma altura maior no `version`. A mesma regra faz o
   `getblocktemplate` responder `-1031` (exceto na regtest).
2. **Sem minerador embutido na regtest.** Lá a PoW é sempre válida, então o
   minerador produziria blocos sem parar e logo passaria do limite de 10
   minutos no futuro. O nó recusa `--mine-address` na regtest e aponta para
   `generatetoaddress`, que fica limitado a 100 blocos por chamada pelo
   mesmo motivo.
3. **Timestamp mínimo do template** é a mediana dos 11 últimos blocos mais
   um, a regra de consenso, e não o timestamp do pai mais um.
4. **`--datadir` é o diretório base:** a rede fica em `<datadir>/<rede>`, e
   o `itacoin.toml` dentro dela. Por isso `--network` e `--datadir` existem
   só na linha de comando: são eles que localizam o arquivo.
5. **`--mine-address` sem `--mine`** deixa o minerador disponível e
   desligado, para ser ligado depois com `setmining`. Sem endereço,
   `setmining` responde `-1030`.
6. **O RPC escuta só em `127.0.0.1` por padrão,** não também em `::1`: em
   máquinas sem IPv6 o bind falharia e impediria a partida. `--rpc-bind ::1`
   continua disponível.
7. **`itacoin-cli` lê a senha de `ITACOIN_RPC_PASSWORD`**, nunca de um
   argumento, que outros usuários veem na lista de processos. Sem
   `--rpc-user`, usa o cookie.
8. **Notificações JSON-RPC** (sem `id`) recebem `204` sem corpo e são
   omitidas da resposta de um lote, como manda a especificação.
9. **`getchaintips` percorre o índice de blocos** dentro do core. É linear
   no número de blocos conhecidos (alguns milissegundos por ano de cadeia), a
   única exceção à regra da seção 4.4.
10. **`getblocktemplate` devolve também `max_timestamp`**, o relógio local
    mais a tolerância de 10 minutos.
11. **Logs da rede:** a variável `ITACOIN_NET_LOG` saiu; o detalhe da rede
    agora é `--log-level info,itacoin_network=debug`.
12. **`handle_block` passou a devolver o veredito** do bloco submetido, para
    o `submitblock`. A lógica não mudou; a análise de impacto o classifica
    como de risco alto por ser o caminho de todos os blocos recebidos.

### Ainda não implementado

- **`testmempoolaccept`:** `Mempool::add` valida e insere no mesmo passo;
  validar sem inserir exige separar as duas fases.
- **Índice de transações** (`--txindex` e `getrawtransaction` de
  transações confirmadas) e **`--reindex`**.
- **Notificações** de bloco e transação (WebSocket ou ZMQ) e **Stratum**.
- **Binário da carteira** consumindo `listunspent` e `sendrawtransaction`.
- **Minerador com PoW real em teste automático:** existe, mas fica marcado
  `#[ignore]`, porque um bloco na dificuldade mínima custa ≈ 2 minutos de
  CPU. Os demais testes usam a regtest.

