# Rede P2P — aprovada

> Aprovada em 2026-11-23, com todos os pontos da seção 11, e implementada em
> `itacoin-network` e `itacoin-mempool`. Nada aqui é regra de consenso: um nó
> que segue outra política de rede continua na mesma cadeia. Segue os
> requisitos 1.7 e 1.8 de [PROTOCOL_REQUIREMENTS.md](PROTOCOL_REQUIREMENTS.md).
> A seção 12 registra os ajustes e o que ainda não foi implementado.

## 1. Modelo de ameaças

| Ameaça | O que o atacante faz | Defesa principal (seção) |
| --- | --- | --- |
| **Sybil** | cria milhares de identidades baratas (IPs, nós) | conexões limitadas por grupo de rede e tabela de endereços com sal secreto (6) |
| **Eclipse** | ocupa todas as conexões de um nó para isolá-lo e mostrar uma cadeia falsa | saídas em grupos de rede distintos, conexões só de blocos, âncoras e *feelers* (6) |
| **Esgotamento de CPU** | envia cabeçalhos (3 ms de Argon2id cada), assinaturas (0,35 ms) ou transações caras | validação do barato para o caro, limites por mensagem e por peer, desconexão imediata (4, 5, 7) |
| **Esgotamento de memória** | anuncia mensagens enormes, órfãos, inventários e endereços em massa | tamanho máximo verificado antes de alocar, pools com teto (3, 7, 8) |
| **Esgotamento de banda** | pede os mesmos blocos repetidamente; propaga transações sem taxa | limites de `getdata`, taxa mínima de relay, *compact blocks* (5, 7, 9) |
| **Spam de cabeçalhos de baixo trabalho** | envia uma cadeia longa e barata que parte do gênese | só guardar ramos com trabalho suficiente (4) |
| **Vigilância** | observa o tráfego para ligar transações a IPs | transporte criptografado, atraso aleatório no relay de transações (2, 8) |
| **Adulteração em trânsito** | altera ou injeta mensagens numa conexão | transporte autenticado (2); tudo o que importa é validado por consenso |

**Fora de escopo.** Não há defesa contra um atacante com mais de 50% do
trabalho da rede (isso é consenso) nem contra quem controla todas as rotas de
internet de um nó. A rede não autentica *quem* é um peer: os peers são
anônimos, como no Bitcoin, e a segurança vem da validação, não da confiança.

## 2. Transporte

### Opções

| Opção | Confidencialidade | Pós-quântico | Complexidade |
| --- | --- | --- | --- |
| Texto puro (Bitcoin antes do BIP 324) | não | — | mínima |
| Estilo BIP 324 com X25519 | sim | não: tráfego gravado hoje pode ser decifrado no futuro | média |
| **Estilo BIP 324 com KEM híbrido X25519 + ML-KEM-768** | **sim** | **sim** | média |

### Proposta

Transporte criptografado obrigatório desde a primeira versão, sem modo de
texto puro na mainnet e na testnet. Uma rede pós-quântica que deixasse o
tráfego exposto a decifragem futura ("grave agora, decifre depois")
permitiria ligar transações a IPs retroativamente.

- **Acordo de chave:** KEM híbrido X25519 + ML-KEM-768, combinado como no
  X-Wing (rascunho da IETF): a chave da sessão só é exposta se os dois forem
  quebrados. As chaves são efêmeras, sem identidade de longo prazo.
- **Cifra:** ChaCha20-Poly1305, já usada pela carteira, com chaves separadas
  por direção e renovação a cada 2^24 mensagens.
- **Sem identidade:** o canal é cifrado mas não autenticado. Um atacante
  ativo pode se colocar no meio, mas não pode observar passivamente, e
  nada muda na segurança do consenso.
- **Crates:** `ml-kem` (RustCrypto, a mesma família do `ml-dsa`),
  `x25519-dalek` e `chacha20poly1305`, todos em Rust puro e com versão fixada.
- **Revisão obrigatória:** o handshake é especificação própria e precisa de
  revisão criptográfica independente antes da mainnet, como o ML-DSA.
- **Regtest** aceita texto puro, para depuração local.

## 3. Enquadramento das mensagens

Dentro do canal cifrado, cada mensagem é:

```text
Message {
    magic:   [u8; 4]   // 4 primeiros bytes do chain_id
    command: u8        // tipo da mensagem
    length:  u32       // tamanho do payload, big-endian
    payload: [u8; length]
}
```

- **`magic`** identifica a rede: `b97fa417` na mainnet e `cdee9e3c` na
  testnet. Um peer de outra rede é desconectado no handshake.
- **Limite antes de alocar** (requisito 1.8): cada `command` tem um tamanho
  máximo (seção 5). O nó lê `command` e `length`, compara com o máximo do tipo
  e só então aloca o buffer. Comando desconhecido ou acima do limite
  desconecta o peer.
- **Payload no codec canônico** (big-endian, largura fixa, decodificação
  estrita). Bytes sobrando desconectam o peer.

## 4. Sincronização

### Cabeçalhos primeiro

1. O nó pede cabeçalhos com um *locator* (até 64 ids, densos perto do tip e
   esparsos para trás) e recebe até **1.000 cabeçalhos** por mensagem
   (146 KB).
2. Cada cabeçalho passa pelas regras do mais barato ao mais caro: encadeamento,
   altura, alvo do ASERT, timestamps e, por último, o Argon2id (3 ms). Os
   cabeçalhos de uma mensagem são verificados em paralelo nos núcleos
   disponíveis.
3. Os blocos são baixados em paralelo de vários peers, até 16 em voo por peer,
   com timeout e troca de peer em caso de lentidão.
4. Cada bloco completo entra por `Chain::submit_block`, que já faz a
   validação completa e a reorganização.

### Assimetria a favor de quem verifica

Mesmo na dificuldade mínima (`POW_LIMIT`), um cabeçalho válido custa em
média 2^15 cálculos de Argon2id ao atacante (≈ 100 s de uma CPU), contra 3 ms
para verificá-lo: uma vantagem de ≈ 33.000×. Inundar um nó com cabeçalhos
*válidos* custa mais ao atacante do que ao nó. Cabeçalhos *inválidos* custam
no máximo uma verificação antes da desconexão.

### Spam de cabeçalhos de baixo trabalho

Uma cadeia barata que parte do gênese ainda ocupa disco se for guardada
inteira. Para evitar isso:

- **`MIN_CHAIN_WORK`:** uma constante, atualizada a cada versão, com o
  trabalho de uma cadeia conhecida. Até que um ramo a ultrapasse, os
  cabeçalhos dele são verificados mas não guardados (pré-sincronização em
  duas fases, como no Bitcoin Core 24).
- **Ramos laterais profundos:** um ramo que se separa mais de 288 blocos
  (≈ 9,6 h) abaixo do tip só é guardado depois de ter mais trabalho que a
  cadeia ativa.

### Blocos órfãos

Blocos com pai desconhecido ficam num pool de no máximo **100 blocos**, por
no máximo **1 hora**, com no máximo 10 por peer. Quando o pai chega, o órfão é
submetido de novo.

## 5. Mensagens

| Mensagem | Conteúdo | Limite |
| --- | --- | --- |
| `version` | versão do protocolo, serviços, altura, horário, nonce, user agent | 200 bytes; user agent ≤ 64 bytes |
| `verack` | — | 0 |
| `ping` / `pong` | nonce | 8 bytes |
| `addr` | endereços com horário e serviços (formato com tipo de rede, para IPv4, IPv6 e Tor v3) | 1.000 endereços |
| `getheaders` | locator + id de parada | 64 ids |
| `headers` | cabeçalhos | 1.000 cabeçalhos |
| `inv` / `getdata` / `notfound` | tipo + id (txid ‖ `witness_hash` para transações) | 1.000 itens |
| `tx` | transação | `MAX_TX_BYTES` |
| `block` | bloco | `MAX_BLOCK_BYTES` |
| `sendcmpct` / `cmpctblock` / `getblocktxn` / `blocktxn` | *compact blocks* (seção 9) | `MAX_BLOCK_BYTES` |
| `feefilter` | taxa mínima que o peer quer receber | 8 bytes |

- **Versão do protocolo:** 1. Uma versão nova pode acrescentar mensagens;
  peers antigos as ignoram só se a negociação no `version` disser que podem.
- **Serviços:** `NETWORK` (serve a cadeia completa) e `WITNESS_PRUNED` (serve
  cabeçalhos e blocos recentes, mas descartou testemunhas antigas, requisito
  1.9).
- **Identificador de transação na rede:** `txid ‖ witness_hash`. Duas
  versões assinadas da mesma transação têm o mesmo txid mas testemunhas
  diferentes, e o nó precisa saber qual das duas o peer tem.

## 6. Conexões e endereços

### Topologia

| Conexão | Quantidade | Propósito |
| --- | --- | --- |
| Saída, relay completo | 8 | blocos, transações e endereços |
| Saída, só blocos | 2 | não repassam transações nem endereços, o que dificulta a um atacante mapear a topologia |
| Entrada | até 117 | total de 125 conexões |
| *Feeler* | 1 a cada 2 min, de curta duração | testa endereços novos e promove os que respondem |

- **Grupos de rede:** no máximo uma conexão de saída por /16 de IPv4 ou /32
  de IPv6. Um atacante com muitos IPs no mesmo provedor ocupa no máximo uma
  saída.
- **Tabela de endereços** no modelo do Bitcoin Core: tabelas "novos" e
  "testados" divididas em baldes escolhidos por hash com um sal secreto local.
  O atacante não consegue prever em que balde seus endereços caem nem
  expulsar todos os endereços legítimos.
- **Âncoras:** as 2 conexões só de blocos são gravadas ao desligar e
  reabertas ao iniciar, para que um reinício não entregue o nó a um atacante
  que inundou a tabela.
- **Despejo de entradas:** quando as entradas estão cheias, a conexão
  despejada é escolhida entre as menos úteis, protegendo peers de grupos de
  rede diferentes, com menor latência e que entregaram blocos e transações
  recentes.

### Descoberta

1. **Sementes DNS** mantidas pelo projeto. Os domínios ainda precisam ser
   definidos.
2. **Sementes fixas** compiladas no binário, como alternativa.
3. **`--connect` e `--addnode`** manuais.

**Portas propostas:** 7210 na mainnet, 17210 na testnet e 17310 na regtest.

## 7. Limites e mau comportamento

| Limite | Valor |
| --- | --- |
| Handshake completo | 60 s |
| `ping` | a cada 2 min; desconexão sem `pong` em 20 min |
| Endereços recebidos | balde de tokens, 0,1 por segundo por peer, rajada de 1.000 |
| Itens de inventário de transação | 7 por segundo por peer, rajada de 1.000 |
| Fila de envio por peer | 5 MB; acima disso o nó para de ler as mensagens desse peer |
| Blocos servidos | sem limite para os 288 mais recentes; histórico limitado por banda configurável |

**Sem pontuação de banimento.** Qualquer violação de protocolo ou regra de
consenso desconecta o peer na hora, e o IP fica desencorajado por 24 horas:
conexões de entrada dele são as primeiras despejadas, e ele não é escolhido
para saída. Isso é o que o Bitcoin Core faz desde 2020. Pontuações graduais
deixavam um atacante abusar até o limite.

## 8. Mempool e relay de transações

| Política | Valor |
| --- | --- |
| Taxa mínima de relay | 1 satoshi por byte (≈ 0,000054 ITC numa transação de 1 input e 2 outputs) |
| Tamanho da mempool | 300 MB (≈ 55 mil transações, ≈ 300 blocos de fila); despejo pela menor taxa por byte |
| Expiração | 14 dias |
| Cadeia de transações não confirmadas | até 25 ancestrais e 25 descendentes |
| Substituição (RBF) | sempre permitida, se a nova paga mais em valor absoluto e por byte, e cobre o relay da substituição |
| Transações órfãs (pai desconhecido) | até 100, por 20 minutos |
| Cache de assinaturas | assinaturas verificadas na mempool não são verificadas de novo no bloco (requisito 1.7) |

- **Validação na mempool,** do barato para o caro: tamanho e forma (já
  feitos pelo codec), taxa mínima, existência dos inputs e
  `validate_spend`. A verificação ML-DSA fica por último.
- **Privacidade:** o anúncio de cada transação sai para cada peer depois de
  um atraso aleatório (Poisson, média de 2 s para saídas e 5 s para
  entradas), o que dificulta descobrir qual nó a criou. O Dandelion++ não é
  proposto: não foi adotado no Bitcoin, por complexidade e risco de DoS.

## 9. Compact blocks

Com assinaturas de 5 KB, propagar só o que falta é a maior economia de banda
da rede (requisito 1.8).

- No estilo BIP 152: o bloco é anunciado como cabeçalho, coinbase e
  **identificadores curtos de 6 bytes** de cada transação. O peer reconstrói
  o bloco com a própria mempool e pede só as transações que não tem.
- **Identificador curto:** SipHash-2-4 de `txid ‖ witness_hash`, com chave
  derivada do cabeçalho e de um nonce por anúncio. Isso impede que um
  atacante prepare colisões antecipadamente.
- **Modo de alta banda** com 3 peers escolhidos: eles enviam o
  `cmpctblock` antes de validar o bloco inteiro, depois de verificar só o
  cabeçalho e a PoW.
- **Efeito:** uma transação já na mempool custa 6 bytes no anúncio do bloco,
  em vez de 5.386. Um bloco cheio cujas transações todos já têm é anunciado
  em ≈ 1,3 KB.

## 10. Implementação

- **Runtime assíncrono:** `tokio`, com versão fixada. É o padrão do
  ecossistema Rust para servidores de rede e tem temporizadores e limites de
  tarefas maduros.
- **Crates:**
  - `itacoin-network`: transporte, enquadramento, máquina de estados do peer,
    tabela de endereços e gerenciador de sincronização;
  - `itacoin-mempool`: política, despejo, RBF e cache de assinaturas, sem
    I/O.
- **Testes obrigatórios:**
  - fuzzing de toda mensagem (`version`, `headers`, `inv`, `addr`,
    `cmpctblock`) com a propriedade de ida e volta dos alvos atuais;
  - rede simulada em processo, determinística, com dezenas de nós,
    partições, latência e um nó atacante;
  - testes adversariais: mensagem acima do limite, *slowloris* (handshake
    lento), inundação de `addr`, tentativa de eclipse e spam de cabeçalhos de
    baixo trabalho;
  - três nós reais em localhost, minerando na regtest e convergindo para o
    mesmo tip depois de uma partição.

## 11. Pontos aprovados

1. **Transporte criptografado obrigatório** com KEM híbrido X25519 +
   ML-KEM-768, sem modo de texto puro fora da regtest, e com revisão
   criptográfica do handshake antes da mainnet.
2. **Topologia:** 8 saídas completas, 2 só de blocos, até 117 entradas e uma
   saída por grupo de rede.
3. **Desconexão imediata** e desencorajamento por 24 horas, sem pontuação de
   banimento.
4. **Cabeçalhos:** 1.000 por mensagem, pré-sincronização com `MIN_CHAIN_WORK`
   e ramos laterais com mais de 288 blocos de profundidade guardados só com
   trabalho maior.
5. **Mempool:** taxa mínima de 1 sat/byte, 300 MB, RBF sempre permitido.
6. **Compact blocks** com identificador curto sobre `txid ‖ witness_hash`.
7. **Portas** 7210 / 17210 / 17310.
8. **`tokio`** como runtime assíncrono.
9. **Sementes DNS:** ainda sem domínios; a lista é configurável e começa vazia.

## 12. Ajustes feitos na implementação

1. **Regtest também é criptografada.** O modo de texto puro não foi
   implementado: uma única forma de transporte é mais simples e mais segura.
2. **`version` ganhou o campo `relay`.** Sem ele, o lado que recebe uma
   conexão só de blocos não saberia que não deve repassar transações nem
   endereços a ela.
3. **Lentidão não é punida.** Timeout de handshake e de `ping` só
   desconectam; o desencorajamento por 24 horas vale para violações de
   protocolo e de consenso.
4. **Transporte:** o cabeçalho de cada quadro (`magic ‖ command ‖ length`) é
   um pacote AEAD próprio, então o comprimento é autenticado e checado antes
   de alocar o payload. Os ids da rede entram no transcript do handshake: um
   peer de outra rede deriva chaves diferentes e falha no primeiro quadro.
5. **Cache de assinaturas** global em `itacoin-crypto::verify_cached`
   (requisito 1.7), usado por `validate_spend`: a assinatura verificada na
   mempool não é verificada de novo no bloco.
6. **Após uma reorganização,** as transações dos blocos desconectados voltam
   à mempool quando continuam válidas, e a mempool é revalidada contra o novo
   tip.

### Ainda não implementado

- **Sementes DNS:** dependem dos domínios do projeto.
- **Tor:** endereços Tor v3 são aceitos no `addr` mas não guardados, e o nó
  não conecta a eles.
- **Anúncio do próprio endereço:** o nó ainda não divulga seu IP externo;
  peers o conhecem por sementes, conexões manuais e repasse de `addr`.
- **Limite de banda para blocos históricos** (seção 7): blocos antigos são
  servidos sem limite.
- **Rede simulada determinística** (seção 10): os testes usam nós reais em
  localhost (três nós em linha, partição e convergência) e um peer adversário
  que fala o protocolo à mão. Um simulador com dezenas de nós e latência
  controlada fica para uma etapa futura.
- **Revisão criptográfica do handshake,** obrigatória antes da mainnet.
