# Consenso — aprovado

> Aprovado em 2026-11-23, com todos os pontos da seção 10, e implementado em
> `itacoin-consensus` e `itacoin-storage::chain`. Fecha os pontos abertos da
> [proposta de emissão](EMISSION_PROPOSAL.md) e fixa os limites do
> [codec](CODEC_PROPOSAL.md). A seção 11 registra os ajustes que a
> implementação exigiu.

## 1. Intervalo de bloco: 120 segundos

| Intervalo | Blocos/ano | Prós | Contras |
| --- | --- | --- | --- |
| 60 s | 525.600 | confirmação rápida | mais órfãos com blocos de até 1 MB; o dobro de cabeçalhos para verificar |
| **120 s** | **262.800** | equilíbrio entre confirmação e propagação | — |
| 600 s | 52.560 | órfãos raros | confirmação lenta; dificuldade reage devagar em uma rede pequena |

Com assinaturas de 5 KB, o tempo de propagação de um bloco cheio pesa mais do
que no Bitcoin. 120 s dá margem para propagar 1 MB, mesmo sem *compact
blocks*, mantendo a taxa de órfãos baixa.

## 2. Emissão

### Duração da era

**`N = 262.800` blocos (≈ 1 ano).** As 100 eras da curva linear duram ≈ 100
anos.

| Era | Emissão da era | Recompensa por bloco | Blocos com +1 satoshi |
| --- | --- | --- | --- |
| 0 | 1.990.000 ITC | 7,57229832 ITC | 150.400 |
| 1 | 1.970.000 ITC | 7,49619482 ITC | 130.400 |
| 50 | 990.000 ITC | 3,76712328 ITC | 201.600 |
| 99 | 10.000 ITC | 0,03805175 ITC | 10.000 |

A soma exata de todas as recompensas, calculada bloco a bloco com essas
regras, é 10.000.000.000.000.000 satoshis = `MAX_SUPPLY`.

### Função de subsídio

```text
subsidy(h):
    era = h / N
    se era >= 100: devolve 0
    E    = (1_990_000 - 20_000 × era) × COIN
    base = E / N
    extra = E % N
    devolve base + (1 se h % N < extra, senão 0)
```

O cálculo usa só divisão e resto inteiros e não estoura `u64` para nenhum
`h`, inclusive `u64::MAX`.

### Gênese, taxas e órfãos

- **Gênese:** recebe a recompensa normal da altura 0, paga ao `WalletId`
  formado só por zeros. Ninguém conhece uma chave cujo hash BLAKE3 seja zero,
  então esses 7,57 ITC ficam queimados. Assim a soma continua exatamente
  `MAX_SUPPLY`, sem alocação inicial e sem caso especial na regra da
  coinbase.
- **Taxas:** vão para o minerador pela coinbase, que pode reivindicar até
  `subsidy(h) + taxas` (já implementado). O que não for reivindicado é
  queimado.
- **Órfãos:** são resolvidos pela regra de cadeia mais pesada (seção 6). O
  pool de blocos com pai desconhecido é política do nó, não consenso: no
  máximo 100 blocos, descartados após 1 hora.

## 3. Prova de trabalho

### Opções

| Algoritmo | Verificação | Mercado de aluguel de hash | Rust puro | Risco principal |
| --- | --- | --- | --- | --- |
| SHA-256d | ~1 µs | enorme (Bitcoin) | sim | uma fração mínima do hash do Bitcoin, alugada por horas, reescreve a cadeia |
| BLAKE3 | 0,2 µs | ASICs existentes (Alephium) | sim | o mesmo, em escala menor |
| RandomX | ~ms, 256 MiB de cache | grande (Monero) | não (C++ via FFI) | aluguel de hash de Monero; dependência nativa |
| **Argon2id, parâmetros próprios** | **3 ms** | **inexistente** | **sim** (já é dependência) | mineração por GPU; ASIC no longo prazo |

O maior risco de uma rede nova com PoW não é a centralização da mineração, e
sim um ataque de 51% feito com hash alugado de uma rede maior que use o mesmo
algoritmo. Um Argon2id com parâmetros exclusivos da ITACOIN não tem esse
mercado. Ele também usa a crate `argon2`, que a carteira já usa, sem código
nativo nem `unsafe`.

### Proposta

```text
pow_hash = Argon2id(
    senha   = cabeçalho codificado (146 bytes, nonce incluído),
    sal     = "ITACOIN:pow:v1" ‖ chain_id,
    m = 4096 KiB, t = 1, p = 1, saída = 32 bytes)

válido se pow_hash ≤ target  (comparação big-endian de 256 bits)
```

- O `block_id` continua sendo o BLAKE3 do cabeçalho: rápido para indexar e
  referenciar. Só a validação de trabalho usa o Argon2id.
- O `chain_id` no sal impede que trabalho feito na testnet valha na mainnet.
- **Custo medido:** 3,0 ms por verificação em um núcleo de um i5-3570. Os
  outros parâmetros medidos foram 1,5 ms com 2 MiB, 6,4 ms com 8 MiB e 13 ms
  com 16 MiB. Sincronizar um ano de cabeçalhos custa ≈ 13 minutos de um
  núcleo, e a verificação de cabeçalhos é paralelizável.
- **Ordem de validação do cabeçalho:** encadeamento, `target` igual ao
  esperado (seção 4) e timestamp, e só então o Argon2id. Um peer que envia
  cabeçalhos com PoW inválida é desconectado na primeira ocorrência.
- **Limitação honesta:** 4 MiB não impede GPUs. O objetivo é negar um mercado
  de aluguel, não impedir hardware dedicado.

## 4. Ajuste de dificuldade: ASERT

Propõe-se o **aserti3-2d**, o algoritmo em uso no Bitcoin Cash desde 2020. Ele
calcula o alvo de cada bloco a partir de uma âncora fixa e do quanto a cadeia
está adiantada ou atrasada em relação ao cronograma ideal:

```text
target(h+1) = target_âncora × 2^((tempo_decorrido − T × (h − h_âncora + 1)) / meia-vida)
```

- **`T = 120 s`; meia-vida = 12 horas (43.200 s, 360 blocos).** Se a cadeia
  fica 12 horas adiantada em relação ao cronograma, a dificuldade dobra; se
  fica 12 horas atrasada, cai pela metade.
- **Âncora = bloco gênese.** Não há janelas nem oscilação, e o ajuste é feito
  a cada bloco.
- **Aritmética exata.** Usa a aproximação cúbica inteira do aserti3-2d
  (expoente em ponto fixo 16.16 e polinômio com os coeficientes publicados),
  divisão com arredondamento para baixo e produto em 512 bits. O resultado é
  limitado a `[1, POW_LIMIT]`.
- **`POW_LIMIT = 2^241 − 1`:** um núcleo de CPU (≈ 330 hashes/s) acha um
  bloco a cada ≈ 2 minutos. É também o alvo do gênese.
- Ele é imune ao *time warp* clássico: o alvo depende do tempo absoluto
  desde a âncora, não de janelas que um minerador possa manipular.

## 5. Timestamps

1. `timestamp > MTP`, a mediana dos timestamps dos 11 blocos anteriores.
2. `timestamp ≤ relógio local + 600 s`. Um bloco além disso não é
   inválido para sempre: o nó o adia até que a regra seja satisfeita.
3. O nó usa o relógio do sistema, sem "tempo ajustado pela rede", que um
   atacante poderia manipular com peers falsos.

## 6. Escolha da cadeia e reorganização

- **Trabalho de um bloco:** `work = ⌊2^256 / (target + 1)⌋`. O trabalho
  acumulado é guardado em 256 bits.
- **Cadeia ativa:** a válida com maior trabalho acumulado. Em caso de empate,
  vale a recebida primeiro.
- **Reorganização:** reverter até o ancestral comum com
  `ChainStore::revert_tip` e aplicar os blocos da nova cadeia. Se um deles
  falhar, o nó desfaz o que aplicou, volta à cadeia anterior e marca o bloco
  inválido e seus descendentes.
- **Sem limite de profundidade no consenso.** O nó apenas registra um alerta
  em reorganizações de mais de 100 blocos. Checkpoints automáticos criam
  divisões permanentes da rede entre nós que viram cadeias diferentes.

## 7. Maturidade da coinbase

**100 blocos (≈ 3 h 20 min).** Uma reorganização de 100 blocos exige refazer
3 h 20 min de todo o trabalho da rede. Abaixo disso, uma coinbase revertida
invalidaria as transações que a gastaram.

## 8. Limites recalculados

Com 120 s, os limites provisórios do codec ficam assim:

| Constante | Antes | Proposta | Efeito |
| --- | --- | --- | --- |
| `MAX_BLOCK_BYTES` | 2.000.000 | **1.000.000** | ~185 transações de 1 input por bloco, ≈ 1,5 tx/s |
| `MAX_BLOCK_SIG_VERIFICATIONS` | 400 | **200** | ≈ 70 ms de verificação por bloco em um núcleo |
| `MAX_TX_BYTES` | 100.000 | 100.000 | sem mudança |

No pior caso, com todos os blocos cheios, a cadeia completa cresce 263 GB por
ano. Um nó que poda testemunhas (requisito 1.9) guarda ≈ 125 bytes por
transação de 1 input, cerca de 6 GB por ano.

## 9. Implementação

- **`itacoin-consensus`:** `subsidy`, `pow_hash`, `check_pow`, ASERT,
  `median_time_past`, trabalho por bloco e um tipo `U256` mínimo, todos sem
  estado e sem I/O.
- **`itacoin-storage`:** índice de cabeçalhos (inclusive de cadeias
  laterais) com altura e trabalho acumulado, e a reorganização descrita na
  seção 6.
- **Testes obrigatórios:**
  - soma de `subsidy(h)` para todo `h` igual a `MAX_SUPPLY`, e zero para
    `h ≥ 100 × N`, inclusive `u64::MAX`;
  - os vetores oficiais do aserti3-2d, rodados com os parâmetros do Bitcoin
    Cash, para provar que a implementação é idêntica antes de aplicar os
    parâmetros da ITACOIN;
  - reorganizações com cadeias concorrentes, bloco inválido no meio da nova
    cadeia e queda do processo durante a reorganização;
  - determinismo: dois nós aplicando os mesmos blocos em ordens de chegada
    diferentes terminam no mesmo tip e no mesmo UTXO set.

## 10. Pontos aprovados

1. **Intervalo de 120 s** e era de 262.800 blocos (emissão em ≈ 100 anos).
2. **Gênese queimado** (recompensa da altura 0 paga ao `WalletId` zero).
3. **Argon2id com 4 MiB** como PoW, ou outra opção da seção 3.
4. **ASERT** com meia-vida de 12 horas e `POW_LIMIT = 2^241 − 1`. No
   lançamento, um minerador muito maior que uma CPU acha blocos rápido até o
   ASERT subir a dificuldade: com 1000× o hash inicial, isso leva ≈ 3.600
   blocos (≈ 27 mil ITC). A alternativa é lançar com uma dificuldade inicial
   maior.
5. **Timestamps:** mediana de 11 blocos e no máximo 10 minutos no futuro.
6. **Maturidade da coinbase** de 100 blocos.
7. **Limites** de 1 MB e 200 verificações por bloco.
8. **Sem limite de profundidade de reorganização** no consenso.

## 11. Ajustes feitos na implementação

1. **O gênese não tem PoW verificada.** O `chain_id` é o id do gênese e
   entra no sal do Argon2id, então a PoW do próprio gênese seria circular.
   O gênese de cada rede é fixado no código (`ConsensusParams::genesis`) e
   aceito pelo id, como na prática ocorre no Bitcoin.
2. **Tempo do pai da âncora.** O ASERT usa o timestamp do *pai* da âncora.
   Como o gênese não tem pai, ele é definido como `timestamp do gênese − T`.
   Assim o bloco seguinte ao gênese mantém o alvo do gênese.
3. **Arredondamento do expoente.** Para ser idêntico ao aserti3-2d, a divisão
   do expoente trunca em direção a zero e o deslocamento aritmético arredonda
   para baixo, como na implementação de referência em C++. A equivalência é
   provada pelos 13.030 vetores oficiais em
   `crates/itacoin-consensus/vectors/`.

Valores fixados:

| Rede | Timestamp do gênese | `chain_id` |
| --- | --- | --- |
| Mainnet | 2027-01-01T00:00:00Z | `b97fa417ac636bb6d901c05e34b4d7785cb4a180b49e3e452ab338c87f0c065c` |
| Testnet | 2026-11-23T00:00:00Z | `cdee9e3c0db32519de594e136843b9aac4a8597441dc3cc7a4fd08f064b2a055` |
| Regtest | 2026-01-01T00:00:00Z | PoW sempre válida e maturidade de 1 bloco, só para testes |

O id e a PoW do gênese da mainnet foram conferidos de forma independente com
as implementações de referência do BLAKE3 e do Argon2 (em C).
