# Storage que escala — aprovado

> Aprovado em 2026-11-23, com todos os pontos da seção 11, e implementado em
> `itacoin-blockchain` (validação pura e bloco podado), `itacoin-storage`,
> `itacoin-mempool`, `itacoin-network`, `itacoin-rpc` e `itacoin-node`.
> Resolve o item 3 dos próximos passos de [REMEDIATION.md](REMEDIATION.md),
> implementa a poda de testemunhas do requisito 1.9 de
> [PROTOCOL_REQUIREMENTS.md](PROTOCOL_REQUIREMENTS.md) e cria o `--reindex`.
> Nada aqui é regra de consenso. A seção 12 registra os ajustes e o que ainda
> não foi implementado.

## 1. Situação atual

| Parte | Hoje | Problema |
| --- | --- | --- |
| UTXO set | inteiro em memória (`HashMap`), espelhado no `redb` a cada bloco, e com o índice por `wallet_id` também em memória | memória cresce com o número de moedas, ≈ 190 bytes cada; a partida lê o conjunto inteiro do disco |
| Blocos | todos guardados com testemunhas, inclusive os de ramos laterais, para sempre | com blocos cheios, 263 GB por ano |
| Undo | guardado para a cadeia ativa | pequeno; não é problema |
| Índice de cabeçalhos | em memória e em disco | ≈ 200 bytes por cabeçalho, ≈ 50 MB por ano; aceitável |
| Escrita | uma transação durável (`fsync`) por bloco | correta; lenta na sincronização inicial em disco rígido |
| Verificação na partida | reconta todas as moedas e compara com a memória | linear no tamanho do conjunto |

**Ordem de grandeza.** Com 10 milhões de moedas, o UTXO set atual ocupa
≈ 1,9 GB de memória. O Bitcoin tem ≈ 170 milhões; uma rede com 1 transação
por segundo e 2 outputs por transação passa de 10 milhões em poucos meses se
as moedas não forem gastas.

## 2. Objetivos e o que não muda

1. **Memória limitada e configurável,** independente do tamanho do UTXO set.
2. **Disco limitado:** um modo que guarda só as testemunhas recentes.
3. **Partida em tempo constante,** sem ler o conjunto inteiro.
4. **Mesma garantia contra quedas:** depois de uma queda, o estado em disco
   está exatamente num bloco, nunca no meio de um.
5. **Mesmas invariantes:** o suprimento total (achado I-03) continua
   verificado a cada bloco aplicado e revertido.

Continuam iguais: um único arquivo `redb`, o índice de cabeçalhos em
memória, o undo da cadeia inteira (seção 5.3) e as regras de validação.

## 3. UTXO set em disco

### 3.1 Opções

| Opção | Memória | Escrita | Recuperação depois de queda |
| --- | --- | --- | --- |
| Tudo em memória (hoje) | proporcional ao conjunto | por bloco | trivial |
| **Disco + cache só de leitura** | **limitada** | **por bloco, como hoje** | **trivial: o disco está sempre no tip** |
| Disco + cache de escrita (o `dbcache` do Bitcoin Core) | limitada | em lotes | refazer os blocos desde o último descarregamento |

O cache de escrita do Bitcoin Core poupa escrita, mas exige refazer blocos
depois de uma queda, e esses blocos precisam estar guardados com
testemunhas ou ser reaplicados sem verificar assinaturas. **Proposta: o
disco continua sendo a verdade a cada bloco, e a memória vira só um cache
de leitura.** O `ChainStore` já escreve as mudanças de moedas em cada
bloco; o que muda é deixar de manter a cópia inteira.

### 3.2 Validação contra uma fonte de moedas

Hoje `UtxoSet::apply_block` valida e altera o `HashMap` ao mesmo tempo. Ele
passa a ser dividido em dois passos:

```text
validate_block(fonte: &impl CoinSource, bloco, regras) -> BlockDiff
    BlockDiff = moedas gastas (com valor, para o undo) + moedas criadas
              + taxas + variação do suprimento

ChainStore::apply(diff)   // uma transação redb: moedas, undo, bloco,
                          // altura, tip e suprimento; depois atualiza o cache
```

- **`CoinSource`** é um trait com `get(&OutPoint) -> Option<Coin>`. Na
  validação de um bloco, a fonte é "cache, depois disco"; na mempool, a
  mesma fonte mais as transações da própria mempool.
- **As regras de consenso não mudam** e ficam todas em `validate_block`,
  sem I/O: o código que hoje decide se um bloco é válido continua sendo o
  mesmo, só lê as moedas de outro lugar.
- **O `UtxoSet` em memória continua existindo** como implementação de
  `CoinSource` para testes, para os vetores e para o fuzzing.

### 3.3 Cache

- **Tamanho configurável:** `--coin-cache <MiB>`, padrão **300 MiB**
  (≈ 1,5 milhão de moedas), mínimo 16.
- **Política:** duas gerações (quente e fria). Uma leitura promove a moeda
  para a geração quente; quando a quente enche, a fria é descartada e a
  quente vira fria. É um LRU aproximado, O(1), sem dependência nova.
- **Moedas criadas entram no cache.** Moedas novas são as mais prováveis de
  serem gastas em seguida (troco, cadeias de transações na mempool).
- **Moedas gastas saem do cache** no mesmo passo em que saem do disco.
- **Ausências não são guardadas:** um input que não existe é raro e custa
  uma leitura.

O custo de uma leitura que falha no cache é uma busca na árvore B do
`redb`, servida pelo cache de páginas do sistema operacional na maioria das
vezes. Um bloco cheio tem ≈ 190 inputs; mesmo com todas as leituras indo ao
disco, isso fica abaixo dos ≈ 70 ms de verificação de assinaturas do mesmo
bloco.

### 3.4 Suprimento total (I-03)

O total de valor das moedas não gastas vira um campo do `META`, atualizado
na mesma transação de cada bloco pela variação calculada em `u128`. Recontar
todas as moedas sai da partida e passa para `--check-utxo` (seção 7), que
percorre a tabela de moedas e compara com o campo.

### 3.5 Índice por `wallet_id`

O índice que hoje existe em memória vai para uma tabela própria:

```text
WALLET_COINS: wallet_id (32) ‖ outpoint (34) → vazio
```

- `listunspent` e `getbalance` viram buscas por prefixo, paginadas pela
  própria ordem da chave, sem carregar nada em memória.
- **Custo:** ≈ 90 bytes de disco por moeda e uma escrita a mais por output.
- **`--no-wallet-index`** desliga o índice; nesse caso `listunspent` e
  `getbalance` respondem `-1030`. Um nó que só minera ou só repassa blocos
  não precisa dele.

## 4. Escrita e sincronização inicial

Uma transação durável por bloco é o certo depois de sincronizado, mas na
sincronização inicial o `fsync` de cada bloco domina o tempo em disco
rígido. O `redb` permite commits não duráveis (`Durability::None`): eles
ficam visíveis, e uma queda volta ao último commit durável, que é sempre um
estado inteiro e consistente.

- **Durante a IBD:** um commit durável a cada **1.000 blocos ou 30
  segundos**, o que vier primeiro, e não duráveis entre eles.
- **Fora da IBD:** todo bloco durável, como hoje.
- **Efeito de uma queda na IBD:** o nó volta até 1.000 blocos e os baixa de
  novo. Nada fica inconsistente, porque cada commit, durável ou não, contém
  um bloco inteiro.

## 5. Poda de testemunhas

### 5.1 Opções

| Modo | Guarda | Disco por ano, blocos cheios | Serve blocos antigos |
| --- | --- | --- | --- |
| **Arquivo** (padrão) | tudo | ≈ 263 GB | sim |
| **Testemunhas podadas** | blocos inteiros recentes; dos antigos, só as transações sem testemunhas e o hash de cada testemunha | ≈ 7,6 GB | não |
| Blocos podados (o `-prune` do Bitcoin) | só blocos recentes | ≈ 0 | não |

Podar as testemunhas guarda 157 bytes por transação de 1 input e 2 outputs,
contra 5.386 da transação inteira, e mantém o histórico de transações
(útil para o futuro `--txindex` e para exploradores). Podar o bloco inteiro
economiza só o resto e perde esse histórico. **Proposta: arquivo por padrão
e `--prune-witnesses` como opção;** a poda de blocos inteiros não é
proposta agora.

### 5.2 Formato de um bloco podado

```text
PrunedBlock {
    header:        BlockHeader          // 146 bytes, o mesmo
    transactions:  List<bytes sem testemunhas>
    witness_hashes: [Hash256; n]        // um por transação
}
```

- Ele continua **verificável sozinho:** o `tx_root` é recalculado a partir
  dos txids e o `witness_root` a partir dos hashes guardados. Um bloco
  podado corrompido no disco é detectado ao ser lido.
- Fica numa tabela própria (`PRUNED`), e a poda move o bloco de `BLOCKS`
  para `PRUNED` numa transação.

### 5.3 O que fica e o que sai

- **Profundidade:** as testemunhas dos últimos **2.880 blocos (4 dias)**
  ficam; `--prune-witnesses=<blocos>` muda isso, com mínimo de **288**, os
  blocos que a rede serve sem limite (seção 7 da
  [rede](NETWORK_PROPOSAL.md)).
- **O undo fica para a cadeia inteira** (≈ 84 bytes por input gasto,
  ≈ 4 GB por ano com blocos cheios). Reverter um bloco usa só o undo, não as
  testemunhas, então um nó podado continua fazendo reorganizações de
  qualquer profundidade, coerente com a decisão de não limitar
  reorganizações no consenso. Os blocos do ramo novo vêm dos peers.
- **Ramos laterais** mais fundos que a profundidade de poda são apagados de
  vez: não fazem parte da cadeia ativa e não ajudam ninguém.
- A poda roda depois de cada bloco novo, apagando no máximo 100 blocos por
  vez para não atrasar a validação.

### 5.4 Rede e RPC

- Um nó podado anuncia `WITNESS_PRUNED` em vez de `NETWORK` (o bit já
  existe em `message.rs`), responde `notfound` para blocos podados e serve
  normalmente os recentes e os cabeçalhos.
- Na sincronização inicial, o nó pede blocos antigos só a peers `NETWORK`.
- `getblock` de um bloco podado devolve as transações sem testemunhas e
  `"witnesses_pruned": true`; com `verbosity = 0` (bloco serializado)
  responde um erro novo, `-1032`, porque o bloco inteiro não existe mais.
- `getblockchaininfo` ganha `pruned`, `prune_height` e as estatísticas do
  cache de moedas.
- **Ligar a poda é só de ida:** desligá-la depois exige baixar a cadeia de
  novo, e o nó recusa partir sem `--prune-witnesses` num banco já podado.

## 6. Reindexação

`--reindex` reconstrói o estado da cadeia a partir dos blocos guardados:

1. Cria um banco novo ao lado (`chain.redb.reindex`) e copia o índice de
   cabeçalhos.
2. Escolhe a cadeia válida de maior trabalho do índice e aplica seus blocos
   em ordem, com commits não duráveis e um durável a cada 1.000 blocos.
3. Ao terminar, troca os arquivos com um `rename` atômico e apaga o antigo.

- **Assinaturas:** blocos com testemunhas são validados por inteiro. Blocos
  podados são validados em tudo menos as assinaturas, que não existem mais;
  elas foram verificadas quando o bloco chegou, e as testemunhas continuam
  amarradas ao bloco pelo `witness_root` e pelos hashes guardados.
- **Uma queda no meio** deixa o banco antigo intacto; o arquivo
  `.reindex` incompleto é descartado na próxima tentativa.
- **Um bloco faltando ou corrompido** interrompe a reindexação com uma
  mensagem que manda apagar o diretório e sincronizar de novo.

## 7. Verificação

| Quando | O que checa | Custo |
| --- | --- | --- |
| Toda partida | esquema, `chain_id`, tip igual ao topo do índice de alturas, presença do suprimento | constante |
| `--check-utxo` | reconta todas as moedas e o índice por `wallet_id` e compara com o suprimento | linear; minutos para dezenas de milhões de moedas |
| `--check-blocks <n>` | revalida os últimos `n` blocos contra o undo | proporcional a `n` |

## 8. Esquema e migração

`SCHEMA_VERSION` passa de 1 para 2: tabelas `WALLET_COINS` e `PRUNED`,
campos de suprimento e de poda no `META`. Nada foi lançado, mas existem
bancos de testnet e regtest. **Proposta: migração automática na abertura,**
numa única transação, que monta o índice por `wallet_id` e o suprimento a
partir da tabela de moedas. Um banco de versão maior que a conhecida
continua sendo recusado.

## 9. Implementação

| Crate | Muda |
| --- | --- |
| `itacoin-blockchain` | `CoinSource`, `validate_block` e `BlockDiff`; `UtxoSet` vira uma implementação de `CoinSource` em memória; formato `PrunedBlock` |
| `itacoin-storage` | moedas lidas do disco com cache de duas gerações, índice por `wallet_id` em tabela, suprimento no `META`, commits em lote na IBD, poda, reindexação, migração do esquema |
| `itacoin-mempool` | `ChainView` passa a receber uma `CoinSource` |
| `itacoin-network` | anúncio de `WITNESS_PRUNED`, `notfound` para blocos podados, preferência por peers `NETWORK` na IBD |
| `itacoin-rpc` | consultas de moedas pelo `Chain` em vez do `UtxoSet`; erro `-1032`; campos novos no `getblockchaininfo` |
| `itacoin-node` | `--coin-cache`, `--prune-witnesses`, `--no-wallet-index`, `--reindex`, `--check-utxo`, `--check-blocks` |

## 10. Testes obrigatórios

- **Equivalência:** a mesma sequência aleatória de blocos (inclusive
  reorganizações) aplicada ao `UtxoSet` em memória e ao `ChainStore` com
  cache mínimo dá exatamente as mesmas moedas, o mesmo suprimento e o mesmo
  índice por `wallet_id`. Esse teste é a prova de que a divisão
  `validate_block`/`apply` não mudou o consenso.
- **Cache:** com 16 MiB e milhares de moedas, toda leitura devolve o mesmo
  que o disco; nenhuma moeda gasta reaparece.
- **Quedas:** processo morto com `SIGKILL` durante a aplicação de um bloco,
  durante um lote não durável da IBD, durante a poda e durante a
  reindexação; ao reabrir, o estado está num bloco inteiro e
  `--check-utxo` passa.
- **Poda:** um nó podado com 300 blocos recebe uma reorganização de 500
  blocos e termina no mesmo tip e no mesmo UTXO set de um nó arquivo; blocos
  podados passam na verificação de roots; um bloco podado adulterado é
  detectado.
- **Rede:** um nó novo sincroniza a partir de um nó arquivo e de um podado
  ao mesmo tempo, pedindo os blocos antigos só ao arquivo.
- **Reindexação:** num nó com e sem poda, `--reindex` reconstrói moedas,
  suprimento e índice iguais aos de antes.
- **Migração:** um banco de esquema 1 criado pela versão atual abre na nova,
  com o mesmo UTXO set.
- **Memória:** com 2 milhões de moedas e `--coin-cache 64`, o processo fica
  abaixo de um teto medido no teste.

## 11. Pontos aprovados

1. **Disco como verdade a cada bloco e cache só de leitura,** em vez de um
   cache de escrita.
2. **Validação dividida em `validate_block` (puro) e `apply`,** com o
   `UtxoSet` em memória mantido para testes e o teste de equivalência como
   prova.
3. **Cache de moedas de 300 MiB por padrão,** com duas gerações.
4. **Índice por `wallet_id` em tabela,** ligado por padrão e desligável com
   `--no-wallet-index`.
5. **Commits em lote na IBD** (durável a cada 1.000 blocos ou 30 s).
6. **Modo arquivo por padrão; `--prune-witnesses`** guardando os últimos
   2.880 blocos inteiros (mínimo 288), undo da cadeia inteira, e sem poda de
   blocos inteiros.
7. **`--reindex`** num banco ao lado, trocado por `rename` atômico, sem
   verificar assinaturas de blocos podados.
8. **Recontagem do UTXO set só com `--check-utxo`;** a partida checa só o
   que é constante.
9. **Migração automática** do esquema 1 para o 2.

## 12. Ajustes feitos na implementação

1. **Ramos laterais não são podados nem apagados.** Apagar blocos laterais
   mais fundos que a profundidade de poda (seção 5.3) impediria exatamente a
   reorganização longa que a seção 10 exige: um ramo concorrente fica
   "lateral" enquanto cresce, e seus blocos antigos seriam apagados antes de
   ele ultrapassar a cadeia ativa. Blocos laterais nunca foram validados e
   precisam das testemunhas para isso; cada um custa PoW real, e a rede já
   limita ramos profundos sem trabalho suficiente.
2. **Blocos podados da antiga cadeia ativa são reaplicados localmente.** Numa
   reorganização de volta, eles são aplicados a partir do armazenamento, sem
   verificar as assinaturas, que este nó já verificou quando o bloco entrou
   na cadeia ativa. Todas as outras regras são verificadas de novo. Antes
   isso exigiria baixar os blocos de novo de peers completos.
3. **Uma falha de leitura nunca invalida um bloco.** A fonte de moedas
   devolve `Result`; um erro de disco vira `UtxoError::Unavailable`, que a
   cadeia trata como erro de armazenamento, e nunca como bloco inválido.
4. **Ramos sem dados:** a ativação pula, com segurança, um candidato cujo
   caminho tenha um bloco sem dados guardados, e um bloco já indexado que
   chegue de novo é guardado e reativado.
5. **O modo de lote** é decidido a cada bloco pela mesma regra de IBD do
   minerador, e o nó grava tudo de forma durável ao desligar.
6. **`--reindex` não verifica de novo as regras de cabeçalho nem a PoW.** Os
   cabeçalhos foram validados quando guardados, e cada corpo é amarrado ao
   seu cabeçalho pelos roots. Verificar 3 ms de Argon2id por bloco
   multiplicaria o tempo da reindexação.
7. **`--check-utxo`** também confere o índice por `wallet_id` nos dois
   sentidos: toda moeda tem entrada no índice e toda entrada aponta para uma
   moeda.
8. **Rede:** havia uma falha anterior a esta etapa que a poda tornou
   visível. Um peer que respondia com uma lista vazia de cabeçalhos (por já
   ter tudo o que o nó conhecia) nunca era escolhido para baixar blocos. Ele
   agora é considerado dono da cadeia até a altura anunciada no `version`.
   Peers podados só recebem pedidos de blocos a até 288 da altura deles.
9. **`redb` compilado com otimização também no perfil de desenvolvimento,**
   como Argon2 e ML-DSA: sem isso, os testes que montam centenas de blocos
   ficavam 12 vezes mais lentos.
10. **Migração testada sem o código da versão 1:** o teste regrava o
    metadado de um banco novo no formato antigo e confere que a abertura o
    atualiza com o mesmo UTXO set.

### Ainda não implementado

- **Teste de memória com milhões de moedas** (seção 10): o limite do cache é
  verificado pelo número de entradas, não por uma medição do processo.
- **Poda de blocos inteiros e de undo antigo,** que a proposta deixou de
  fora.
- **Índice de transações** (`--txindex`), que a poda de testemunhas deixa
  possível.

