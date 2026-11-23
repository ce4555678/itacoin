# Carteira — aprovado

> Aprovado em 2026-11-23, com todos os pontos da seção 12, e implementado em
> `itacoin-wallet` (derivação, backup, formato v3 e montador),
> `itacoin-wallet-cli` (binário `itacoin-wallet`), `itacoin-process`
> (proteções compartilhadas com o nó) e no RPC do
> [nó](NODE_PROPOSAL.md). Nada aqui é regra de consenso. A seção 13
> registra os ajustes e o que ainda não foi implementado.

## 1. Escopo e fronteiras

| Componente | Faz | Não faz |
| --- | --- | --- |
| `itacoin-wallet` (biblioteca) | derivação de chaves, backup, arquivo criptografado, seleção de moedas, montagem e assinatura | I/O de rede |
| `itacoin-wallet-cli` (binário `itacoin-wallet`) | comandos, entrada de senha, arquivo de estado, chamadas ao RPC | guardar chave decifrada entre comandos |
| `itacoin-node` | fornece moedas, taxas e o envio, por RPC | ver qualquer chave privada |

- **Sem processo residente.** Cada comando abre o arquivo, decifra a chave
  só se precisar assinar ou derivar, faz o trabalho e termina. Não existe
  carteira "destravada" esperando na memória.
- **A carteira não valida a cadeia.** Ela confia no nó a que se conecta,
  que deve ser o do próprio usuário (seção 7.3).
- **O binário fica num crate próprio** para que a biblioteca continue sem
  `tokio`, `hyper` e `serde`.

## 2. Modelo de ameaças

| Ameaça | Defesa principal (seção) |
| --- | --- |
| **Perda do computador ou do arquivo** | backup do segredo mestre, com checksum forte (4) |
| **Roubo do arquivo** | Argon2id 64 MiB e XChaCha20-Poly1305, já implementados; senha de 12 bytes ou mais |
| **Leitura da memória por outro processo** | sem core dump, processo não *dumpable*, chave decifrada só durante a assinatura (9) |
| **Senha vista por outros usuários** | senha nunca em argumento nem em variável de ambiente (9) |
| **Erro de digitação no endereço ou no valor** | Bech32m com prefixo de rede, valor decimal exato e confirmação antes de enviar (8) |
| **Taxa absurda por engano** | limite de taxa com confirmação extra (6.5) |
| **Gastar a mesma moeda duas vezes por engano** | moedas já gastas na mempool ficam de fora (7.1) |
| **Nó desonesto** | fora de escopo: a carteira confia no nó; ele pode esconder moedas ou mentir sobre confirmações, mas não pode gastar nada |

**Fora de escopo:** malware com o mesmo usuário rodando enquanto a senha é
digitada, e quem controla o sistema operacional. Isso exige carteira de
hardware, que ainda não existe para ML-DSA.

## 3. Chaves

### 3.1 Opções

| Modelo | Backup | Privacidade | Observação |
| --- | --- | --- | --- |
| Uma chave por carteira (o formato atual, `ITCW` v2) | uma vez | ruim: todo pagamento cai no mesmo endereço | simples |
| Chaves aleatórias independentes | a cada endereço novo | boa | backup antigo perde fundos novos |
| **Segredo mestre + derivação determinística** | **uma vez** | **boa** | sem derivação pública (3.3) |

**Proposta: um segredo mestre de 32 bytes do qual todas as chaves são
derivadas.**

### 3.2 Derivação

O ML-DSA gera um par de chaves a partir de uma semente de 32 bytes
(`ML-DSA.KeyGen_internal(ξ)` do FIPS 204, já exposto como
`PrivateKey::from_seed`). A semente da chave número `i` é:

```text
ξ(rede, ramo, i) = BLAKE3-keyed(
    chave    = segredo mestre,
    mensagem = "ITACOIN:wallet:key:v1" ‖ rede (u8) ‖ ramo (u8) ‖ i (u32 BE))

ramo 0 = endereços de recebimento, ramo 1 = troco
```

- **A rede entra na derivação.** O mesmo backup serve para testnet e
  mainnet, mas as chaves são diferentes, então os endereços das duas redes
  não podem ser ligados entre si.
- **Recebimento e troco em ramos separados,** como no BIP 44: a carteira
  sabe o que é troco sem guardar nada, e uma restauração recupera os dois.
- **BLAKE3 com chave** é uma PRF, já é dependência e não tem extensão de
  comprimento. Derivar uma chave custa ≈ 1 ms (o keygen do ML-DSA).

### 3.3 Sem derivação pública

No BIP 32, uma chave pública estendida (*xpub*) gera os endereços sem a
chave privada, o que permite carteiras só de leitura. Não existe construção
equivalente para ML-DSA: a chave pública não é um ponto de curva que se
possa somar. **A derivação é só privada.** Para compensar:

- a carteira **pré-deriva um estoque de endereços** (100 de recebimento e
  100 de troco) quando tem a senha, e guarda só os `wallet_id` no arquivo
  de estado. Pedir um endereço novo não exige senha até o estoque acabar;
- uma **carteira só de leitura** é uma lista exportada de endereços, sem
  capacidade de gerar novos.

### 3.4 Restauração

A restauração deriva endereços em lotes de 100 e pergunta ao nó, por
`listunspent`, quais têm moedas. Ela para depois de 100 endereços seguidos
sem moedas em cada ramo (*gap limit*). O nó só conhece moedas não gastas,
então um endereço já esvaziado parece vazio. Como a carteira entrega
endereços em ordem e o estoque tem 100, isso só perde fundos se o usuário
pedir mais de 100 endereços seguidos que nunca recebam nada; o comando
`rescan --gap N` cobre esse caso.

## 4. Backup

### 4.1 Opções

| Formato | Prós | Contras |
| --- | --- | --- |
| BIP 39, 24 palavras | familiar, fácil de escrever à mão | carteiras de Bitcoin aceitam a frase e derivam outras chaves, e o usuário acha que perdeu os fundos; checksum de 8 bits |
| Hex, 64 caracteres | trivial | sem checksum: um erro de cópia passa despercebido |
| **Bech32m, prefixo `itcseed`** | **checksum que detecta qualquer erro em até 4 caracteres; sem maiúsculas e minúsculas; QR alfanumérico; impossível confundir com uma frase de Bitcoin** | menos familiar; 67 caracteres para copiar |
| SLIP-39 ou codex32 (k de n partes) | backup dividido entre pessoas ou lugares | complexo; codex32 também é Bech32 e pode ser uma extensão futura |

### 4.2 Proposta

```text
itcseed1 ‖ Bech32m(versão = 0 (1 byte) ‖ segredo mestre (32 bytes))
```

- **Igual para todas as redes,** porque a rede entra na derivação (3.2).
- **A versão** permite mudar a derivação no futuro sem ambiguidade: uma
  versão desconhecida é recusada, não interpretada.
- **Exibido uma vez na criação**, com a exigência de redigitar os últimos
  8 caracteres, e depois só pelo comando `backup`, que pede a senha.
- **Sem senha adicional no backup** (como a *passphrase* do BIP 39) nesta
  versão: uma senha esquecida torna o backup inútil, e o ganho só existe
  contra quem acha o papel.

Isso responde à ressalva do README ("nenhuma frase sem um formato de backup
interoperável para ML-DSA"): o formato é especificado aqui, com versão e
vetores de teste, e não finge ser BIP 39.

## 5. Arquivos

### 5.1 Localização

```text
~/.itacoin/wallets/<nome>/
    wallet.itcw          segredo mestre criptografado (ITCW v3), 0600
    state-testnet.json   estado público por rede, 0600
    state-mainnet.json
```

O arquivo secreto vale para todas as redes; o estado é separado por rede.
O diretório é criado com 0700. O nome padrão é `default`.

### 5.2 `ITCW` versão 3

O mesmo formato da versão 2, com dois significados novos:

- o texto cifrado é o **segredo mestre** (32 bytes, o mesmo tamanho da
  semente da v2), não a semente de uma chave;
- o campo de 32 bytes do cabeçalho deixa de ser um `wallet_id` e passa a ser
  uma **impressão digital**: `internal_hash("itacoin:wallet:fingerprint:v1",
  segredo mestre)`. Ela identifica a carteira antes de decifrar, como a v2
  fazia, sem revelar nenhum endereço.

Arquivos v2 continuam legíveis e são tratados como **carteira de chave
única** (sem derivação): `itacoin-wallet import-v2` os aceita, mas não
existe backup `itcseed` para eles.

### 5.3 Estado

O estado é JSON, legível, sem segredos, mas privado (ele liga todos os
endereços da carteira):

| Campo | Conteúdo |
| --- | --- |
| `fingerprint` | a do `wallet.itcw`; um estado de outra carteira é recusado |
| `generation` | a última geração vista do arquivo secreto (achado V-04) |
| `keys` | `wallet_id`, ramo, índice e rótulo de cada endereço derivado |
| `next` | próximo índice entregue em cada ramo |
| `sent` | diário das transações enviadas: txid, transação em base64url, inputs, taxa, horário e estado (`mempool`, `confirmada`, `substituída`) |

- **Rollback (V-04):** a carteira recusa um `wallet.itcw` com geração menor
  que a do estado. A proteção é parcial: quem consegue reverter os dois
  arquivos juntos passa. Ela pega o caso comum, a restauração acidental de
  uma cópia antiga com a senha antiga.
- **Perder o estado não perde fundos:** ele é reconstruído pela restauração
  (3.4). Perde-se só rótulos e o diário.

## 6. Montagem de transações

### 6.1 Tamanho

O tamanho de uma transação é exato antes de assinar, porque chaves e
assinaturas têm tamanho fixo:

```text
bytes = 7 + 36 × inputs + 41 × outputs + 5.261 × chaves distintas
```

Uma transação de 1 input e 2 outputs ocupa 5.386 bytes. A taxa é
`bytes × taxa por byte`, sem estimativa e sem margem.

### 6.2 Seleção de moedas por chave

Cada chave distinta custa 5.261 bytes; cada input a mais da mesma chave,
só 36. O codec já permite que vários inputs compartilhem uma testemunha
(`witness_index`, requisito 1.6). Por isso a unidade de seleção é o
**grupo de moedas de uma chave**, não a moeda:

1. Agrupa as moedas maduras e não gastas na mempool por `wallet_id`.
2. Se um grupo sozinho cobre valor + taxa, escolhe o **menor grupo que
   cobre**.
3. Senão, soma grupos do maior para o menor até cobrir.
4. **Gasta sempre o grupo inteiro.** Depois que uma chave assina, a chave
   pública fica exposta e as outras moedas dela já estão ligadas à
   transação; deixá-las para trás não protege nada e custaria outra
   testemunha depois.

Uma transação tem no máximo 100 KB, o que comporta **18 chaves**. Se o
pagamento exigir mais, a carteira recusa e sugere consolidar antes
(`consolidate`), em vez de montar várias transações sem avisar.

### 6.3 Troco

- **Troco vai para um endereço novo do ramo 1** por padrão, para não ligar
  o troco ao pagamento. Custo: gastar esse troco depois exige uma
  testemunha a mais, ≈ 0,00005 ITC na taxa mínima.
- **`--change-to-input`** devolve o troco à chave do maior input, para
  quem prefere pagar menos taxa a ter privacidade.
- **Poeira:** um troco menor que o custo de gastá-lo depois com uma chave
  nova (5.297 bytes × taxa) vai para a taxa, em vez de virar uma moeda que
  custa mais para gastar do que vale.

### 6.4 Taxa

O nó não estima taxas hoje. A proposta é um método novo, `estimatefee
blocos` (seção 7.2), e um alvo padrão de **6 blocos (12 minutos)**.
`--fee-rate N` fixa a taxa em satoshis por byte.

### 6.5 Proteções

- **Limite de taxa:** acima de 1% do valor enviado ou de 1.000 sat/byte, a
  carteira pede uma segunda confirmação explícita.
- **Confirmação antes de enviar:** destino, valor, taxa, taxa por byte,
  troco e número de chaves usadas. `--yes` pula a pergunta, para scripts.
- **`--dry-run`** monta e assina, mostra o resumo e a transação em
  base64url, e não envia.
- **Valores na entrada** em ITC decimal exato (`Amount::from_itc_str`, até 8
  casas) ou em satoshis com `--sat`. Nunca ponto flutuante.

### 6.6 Substituição (RBF)

A mempool sempre aceita substituição que pague mais. `bumpfee <txid>`
remonta a transação do diário com os mesmos inputs e uma taxa maior,
tirando a diferença do troco (ou acrescentando um grupo, se o troco não
bastar), e a envia. O diário marca a anterior como `substituída`.

## 7. Integração com o nó

### 7.1 Métodos usados

| Método | Uso |
| --- | --- |
| `listunspent` | moedas, saldo e restauração |
| `sendrawtransaction` | envio |
| `getmempoolentry`, `gettxout`, `getblockchaininfo` | estado das transações do diário e altura |
| `estimatefee` (novo) | taxa |

### 7.2 Mudanças no RPC do nó

1. **`listunspent ... include_mempool`** (padrão `false`). Com `true`, cada
   moeda ganha `spent_in_mempool`, e outputs não confirmados para os
   endereços pedidos aparecem com `confirmations: 0`. Sem isso, a carteira
   tentaria gastar de novo uma moeda que ela mesma acabou de gastar. A
   mempool já tem o índice `spent_by`; falta expô-lo.
2. **`estimatefee blocos`**: ordena a mempool por taxa por byte e acumula os
   bytes. Se tudo couber em `blocos × MAX_BLOCK_BYTES`, devolve a taxa
   mínima de relay; senão, a taxa da transação nessa posição mais 1. É uma
   estimativa simples, sem histórico, suficiente enquanto os blocos não
   estiverem cheios.

### 7.3 Nó remoto

`--rpc-connect` e `--rpc-user` funcionam como no `itacoin-cli`. Com um nó
que não está em loopback, a carteira avisa uma vez: **o operador desse nó
vê todos os endereços da carteira** em cada `listunspent` e pode mentir
sobre saldo e confirmações (sem poder gastar nada).

## 8. Comandos

```text
itacoin-wallet --network <rede> [--wallet <nome>] [--rpc-connect ...] <comando>
```

| Comando | Senha | Faz |
| --- | --- | --- |
| `create` | define | gera o segredo, mostra o backup e exige a confirmação |
| `restore` | define | lê o `itcseed1…` e procura moedas (3.4) |
| `backup` | sim | mostra o `itcseed1…` de novo |
| `receive [--label T]` | não* | entrega o próximo endereço de recebimento |
| `addresses` | não | lista endereços, rótulos e saldo de cada um |
| `balance` | não | saldo maduro, imaturo e não confirmado |
| `coins` | não | moedas agrupadas por chave |
| `send <endereço> <valor>` | sim | monta, confirma, assina e envia (6) |
| `consolidate [--max-keys N]` | sim | junta grupos de várias chaves num endereço novo |
| `bumpfee <txid> [--fee-rate N]` | sim | substitui uma transação do diário (6.6) |
| `history` | não | o diário, com o estado de cada transação |
| `rescan [--gap N]` | sim | refaz a procura de moedas |
| `passwd` | sim | troca a senha e incrementa a geração |
| `info` | não | impressão digital, rede, nó, contagem de endereços |
| `import-v2 <arquivo>` | sim | adota uma carteira de chave única |

\* Só quando o estoque de 100 endereços acaba é que `receive` pede a senha
para derivar mais.

## 9. Proteções de processo e senha

1. **Na partida:** `RLIMIT_CORE = 0`, `PR_SET_DUMPABLE = 0` e `umask(077)`,
   com o mesmo código `rustix` do nó, movido para um módulo comum.
2. **Sem `mlock`.** `mlockall` existe com API segura no `rustix`, mas o
   limite padrão de memória travada (`RLIMIT_MEMLOCK`) costuma ser 8 MiB,
   e o Argon2id usa 64 MiB: com `MCL_FUTURE` as alocações falhariam, e sem
   ele o heap não fica coberto. A recomendação documentada é swap
   criptografado. Como o processo dura segundos e a chave decifrada só
   existe durante a assinatura, a exposição é curta.
3. **Senha:** lida do terminal com o eco desligado (`tcsetattr` do
   `rustix`, sem dependência nova). Sem terminal, lida da primeira linha da
   entrada padrão, para scripts. **Nunca** de argumento nem de variável de
   ambiente.
4. **Zeroização:** segredo mestre, sementes derivadas, senha e texto do
   backup em `Zeroizing`; a chave privada já é zeroizada pela biblioteca.

## 10. Organização do código

| Crate | Novos módulos | Novas dependências |
| --- | --- | --- |
| `itacoin-wallet` | `hd` (segredo mestre e derivação), `backup` (`itcseed`), `builder` (seleção, troco, poeira e montagem, sem I/O), formato v3 | — (`blake3` e `bech32` já são dependências do workspace) |
| `itacoin-wallet-cli` | comandos, estado JSON, senha, RPC | `itacoin-rpc` (cliente), `clap`, `serde`, `serde_json`, `rustix` |
| `itacoin-mempool` | acessor `spent_by` | — |
| `itacoin-rpc` | `estimatefee`, `include_mempool` | — |

As proteções de processo saem de `itacoin-node::process` para um módulo
compartilhado pelos dois binários.

## 11. Testes obrigatórios

- **Derivação:** vetores fixos (segredo mestre → `wallet_id` para cada rede,
  ramo e alguns índices), para que uma mudança acidental quebre o teste;
  redes e ramos diferentes nunca dão a mesma chave.
- **Backup:** ida e volta; toda troca de 1 a 4 caracteres é detectada;
  versão desconhecida, prefixo errado e maiúsculas misturadas são recusados.
- **Montagem:**
  - o tamanho calculado é igual ao tamanho codificado, e a taxa é exata;
  - grupos inteiros, menor grupo suficiente, limite de 18 chaves, poeira
    para a taxa, troco no ramo 1;
  - fundos insuficientes, moedas imaturas e moedas gastas na mempool;
  - toda transação montada passa em `validate_spend`;
  - fuzzing do seletor com conjuntos aleatórios de moedas: sem panic, e
    `inputs = outputs + taxa` sempre.
- **Arquivo:** v3 com senha errada, adulterado e com geração menor que a do
  estado; leitura de v2.
- **Ponta a ponta,** com o binário do nó na regtest: `create`, `receive`,
  `generatetoaddress` para o endereço, `send`, confirmação, `bumpfee`
  antes da confirmação, e `restore` a partir do backup encontrando o mesmo
  saldo num diretório vazio.

## 12. Pontos aprovados

1. **Binário separado, sem processo residente;** a chave só é decifrada
   para assinar ou derivar.
2. **Segredo mestre e derivação BLAKE3 com chave** por rede, ramo e índice;
   sem derivação pública, com estoque de 100 + 100 endereços pré-derivados.
3. **Backup em Bech32m `itcseed1…`** com versão, em vez de 24 palavras.
4. **`ITCW` v3** com o segredo mestre e impressão digital no cabeçalho; v2
   aceito como carteira de chave única.
5. **Seleção por grupos inteiros de chave,** troco em endereço novo, poeira
   para a taxa e limite de 18 chaves por transação.
6. **Taxa por `estimatefee`** com alvo de 6 blocos, segunda confirmação
   acima de 1% do valor ou de 1.000 sat/byte, e `bumpfee` por RBF.
7. **Mudanças no RPC:** `listunspent ... include_mempool` e `estimatefee`.
8. **Sem `mlock`;** core dump desligado, processo não *dumpable*, senha só
   pelo terminal ou pela entrada padrão.
9. **Arquivos em `~/.itacoin/wallets/<nome>/`,** com o estado separado por
   rede.

## 13. Ajustes feitos na implementação

1. **Vetores de derivação conferidos de forma independente:** as sementes
   dos testes foram recalculadas com a implementação de referência do
   BLAKE3 (pacote Python `blake3`) e batem byte a byte.
2. **`create` só grava depois da confirmação do backup.** Se os 8 últimos
   caracteres não conferem, nada é escrito.
3. **O backup é lido do terminal sem eco** (ou da entrada padrão), nunca de
   um argumento, como a senha.
4. **Estado criado sob demanda:** o primeiro comando numa rede nova pede a
   senha e deriva o estoque de endereços dessa rede.
5. **Carteira v2 (chave única):** `receive` devolve sempre o mesmo endereço
   e o troco volta para a mesma chave.
6. **`send` aceita um destino por vez.** O montador aceita vários; a linha
   de comando para pagamentos múltiplos fica para depois.
7. **Estado das transações enviadas** (`history`): `confirmed` quando a
   transação saiu da mempool e todos os seus inputs foram gastos, `dropped`
   quando saiu com algum input ainda livre. Sem índice de transações no nó,
   a carteira não distingue uma confirmação de um conflito com outra
   transação que gastou as mesmas moedas.
8. **`bumpfee`** usa como piso `⌈taxa antiga / tamanho antigo⌉ + taxa mínima
   de relay`, o que satisfaz a regra de substituição da mempool. O troco vai
   para o mesmo endereço da transação original, sem gastar um índice novo; a
   substituição de uma consolidação varre as mesmas moedas.
9. **`consolidate`** junta primeiro os grupos de menor valor, que são os mais
   caros de gastar, num endereço novo do ramo de troco.
10. **`listunspent ... include_mempool`** devolve os outputs não confirmados
    só na primeira página, a que não tem cursor.
11. **As proteções de processo** saíram de `itacoin-node` para o crate
    `itacoin-process`, que também lê senhas sem eco (`tcsetattr`) e grava
    arquivos privados de forma atômica.
12. **Mensagens da linha de comando em inglês,** como as do nó e do
    `itacoin-cli`.

### Ainda não implementado

- **Exportação de endereços** para uma carteira só de leitura (seção 3.3).
- **Pagamentos múltiplos** pela linha de comando.
- **Reenvio automático** de transações `dropped`.
- **`mlock`,** pelos motivos da seção 9.

