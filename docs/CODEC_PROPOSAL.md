# Codec canônico — aprovado

> Aprovado em 2026-11-23, com todos os pontos da seção 9, e implementado em
> `itacoin-codec`, `itacoin-transaction` e `itacoin-blockchain` (achado P-01
> da auditoria). Os valores dos limites da seção 5 são provisórios até a
> aprovação do intervalo de bloco. Segue os requisitos de
> [PROTOCOL_REQUIREMENTS.md](PROTOCOL_REQUIREMENTS.md).

## 1. Princípios

1. **Uma única codificação por valor.** Para todo valor válido existe
   exatamente uma sequência de bytes aceita, e todo byte aceito decodifica e
   recodifica para os mesmos bytes. Hashes, txids e deduplicação dependem disso.
2. **Sem inteiros de tamanho variável.** Todo campo tem largura fixa. Isso
   elimina a classe de bugs de varint não mínimo (dois encodings para o mesmo
   número) e permite calcular o tamanho de uma lista antes de alocá-la.
3. **Inteiros em big-endian.** É o que `hash_parts` já usa para os prefixos de
   tamanho. Além disso, a ordem dos bytes coincide com a ordem numérica, o que
   torna as chaves do `itacoin-storage` ordenáveis sem conversão.
4. **Decodificação estrita.** O decodificador recusa bytes sobrando no final,
   versões e tipos desconhecidos, contagens fora dos limites e valores fora do
   intervalo. Ele nunca entra em panic e nunca aloca mais do que o tamanho da
   entrada justifica.
5. **Testemunhas separadas.** Chaves públicas e assinaturas ficam numa seção
   própria, fora do txid (requisito 1.2).

## 2. Tipos básicos

| Tipo | Bytes | Codificação |
| --- | --- | --- |
| `u8`, `u16`, `u32`, `u64` | 1, 2, 4, 8 | inteiro sem sinal, big-endian |
| `Hash256`, `TransactionId`, `BlockId`, `WalletId` | 32 | bytes crus |
| `Amount` | 8 | `u64`, deve estar em `1..=MAX_SUPPLY` quando for valor de output |
| `PublicKey` | 1952 | codificação FIPS 204, validada por `PublicKey::from_bytes` |
| `Signature` | 3309 | codificação FIPS 204, validada por `Signature::from_bytes` |
| `List<T>` | 2 + n × \|T\| | contagem `u16` seguida dos elementos |

Não há tipo de bytes de tamanho livre: nenhum campo do protocolo carrega dados
arbitrários nesta versão.

## 3. Transação

### Estrutura

```text
Transaction {
    version:  u16                 // = 1
    kind:     u8                  // 0 = normal, 1 = coinbase
    body:     NormalBody | CoinbaseBody
    witnesses: [Witness]          // só em kind = 0; contagem implícita, ver abaixo
}

NormalBody {
    inputs:  List<Input>          // 1..=MAX_TX_INPUTS
    outputs: List<Output>         // 1..=MAX_TX_OUTPUTS
}

CoinbaseBody {
    height:  u64                  // altura do bloco; torna o txid único
    outputs: List<Output>         // 1..=MAX_TX_OUTPUTS
}

Input {
    prev_txid:     TransactionId  // 32
    prev_index:    u16            // 2
    witness_index: u16            // 2   → 36 bytes
}

Output {
    kind:      u8                 // 0 = pagamento a WalletId ML-DSA-65
    amount:    Amount             // 8
    wallet_id: WalletId           // 32  → 41 bytes
}

Witness {
    public_key: PublicKey         // 1952
    signature:  Signature         // 3309 → 5261 bytes
}
```

### Uma testemunha por chave, não por input

Cada input aponta, por `witness_index`, para a testemunha que o autoriza.
Vários inputs do mesmo `wallet_id` compartilham uma só chave e uma só
assinatura (requisito 1.6). Uma consolidação de 50 inputs de uma carteira
ocupa ~7 KB, contra ~263 KB com uma testemunha por input.

Regras de forma, verificadas pelo codec sem consultar o UTXO set:

1. O número de testemunhas é `max(witness_index) + 1`. Ele não é serializado,
   porque é derivável.
2. **Ordem canônica:** a primeira ocorrência de cada índice, percorrendo os
   inputs em ordem, deve ser 0, 1, 2, …, sem saltos. Assim toda testemunha é
   referenciada, e o arranjo de índices tem uma só forma para um mesmo
   agrupamento de inputs.

Regras de consenso, verificadas com o UTXO set:

3. Todo input que aponta para a testemunha `w` gasta um output cujo
   `wallet_id` é igual a `wallet_id(w.public_key)`.
4. Duas testemunhas não podem ter o mesmo `wallet_id`.

`witness_index` faz parte do txid. Isso não reabre a maleabilidade: um
terceiro não consegue mudar os índices sem invalidar as assinaturas, que
commitam ao txid.

### Identificadores

```text
txid        = transaction_hash(bytes de version ‖ kind ‖ body)
witness_hash = H("itacoin:witness:v1", bytes da seção de testemunhas)
```

- O txid não cobre testemunhas (requisito 1.2). Assinar de novo a mesma
  transação, com assinatura hedged, produz bytes diferentes mas o mesmo txid.
- A coinbase tem seção de testemunhas vazia; seu `witness_hash` é o hash do
  vazio no domínio de testemunha.
- `H` é `hash_parts` com um novo contexto de derivação em `itacoin-crypto`.

### Mensagem assinada (sighash)

Todas as testemunhas de uma transação assinam a mesma mensagem, no domínio
`SigningDomain::Transaction`:

```text
sighash = H("itacoin:sighash:v1",
            chain_id,              // 32 bytes: id do bloco gênese da rede
            txid,
            spent_outputs_hash)    // hash dos outputs gastos, na ordem dos inputs
```

- **`chain_id`** impede que uma transação assinada na testnet seja válida na
  mainnet (proteção contra replay entre redes).
- **`spent_outputs_hash`** commita aos valores e `wallet_id`s gastos. Uma
  carteira offline ou de hardware pode então confiar no valor que lhe
  informam: se mentirem, a assinatura não valida. É a lição do BIP 143.

### Taxa

`taxa = Σ inputs − Σ outputs`, calculada com `Amount::checked_add`/`checked_sub`
(requisito 2.1), e cobrada sobre o tamanho total da transação, testemunhas
incluídas, sem desconto (requisito 1.5).

### Tamanhos

| Transação | Bytes |
| --- | --- |
| 1 input, 2 outputs | 3 + 2 + 36 + 2 + 82 + 5261 = **5386** |
| 10 inputs da mesma carteira, 1 output | 3 + 2 + 360 + 2 + 41 + 5261 = **5669** |
| Coinbase, 1 output | 3 + 8 + 2 + 41 = **54** |

## 4. Bloco

### Cabeçalho (146 bytes, fixo)

```text
BlockHeader {
    version:      u16        // = 1
    prev_block:   BlockId    // 32
    tx_root:      Hash256    // 32  merkle_root dos txids
    witness_root: Hash256    // 32  merkle_root dos witness_hash
    timestamp:    u64        // 8   segundos Unix
    target:       Hash256    // 32  alvo de PoW completo, big-endian
    nonce:        u64        // 8
}
```

- **`block_id = block_hash(cabeçalho)`.** O hash usado na prova de trabalho
  depende do desenho de PoW, que ainda não foi aprovado. Ele pode ser o
  mesmo ou outro.
- **Dois roots.** Com `tx_root` separado, um cliente leve prova a inclusão de
  uma transação só com txids. Com `witness_root`, o bloco commita às
  testemunhas (requisito 1.2), e um nó que poda testemunhas antigas mantém os
  dois roots (requisito 1.9).
- **`target` com 32 bytes**, em vez do `nBits` compacto do Bitcoin. O formato
  compacto tem mais de uma representação para o mesmo alvo. Aqui o consenso
  exige igualdade exata com o alvo calculado, e os 28 bytes extras são
  irrelevantes perto de uma testemunha de 5 KB.

### Corpo

```text
Block {
    header:       BlockHeader
    transactions: u32 contagem + transações completas, em ordem
}
```

A primeira transação é a coinbase, e somente ela tem `kind = 1`. A altura
fica na coinbase, e não no cabeçalho.

## 5. Limites de consenso propostos

Os números são ponto de partida. Eles devem ser recalculados quando o
intervalo de bloco for aprovado junto com a [emissão](EMISSION_PROPOSAL.md).

| Constante | Valor | Motivo |
| --- | --- | --- |
| `MAX_BLOCK_BYTES` | 2.000.000 | ~370 transações de 1 input; ~1 MB/min se o bloco for de 2 min |
| `MAX_BLOCK_SIG_VERIFICATIONS` | 400 | ~140 ms de verificação em um núcleo (0,35 ms cada) |
| `MAX_TX_BYTES` | 100.000 | ~18 testemunhas; limita o custo de uma transação isolada na mempool |
| `MAX_TX_INPUTS` | 1.000 | 36 KB de inputs; cabe com uma testemunha por carteira |
| `MAX_TX_OUTPUTS` | 1.000 | 41 KB de outputs |

O decodificador recebe o limite de bytes antes de ler. Como todos os campos
têm largura fixa, ele confirma `contagem × tamanho ≤ bytes restantes` antes de
alocar cada lista (requisito 1.8).

## 6. Ordem de validação

Do mais barato para o mais caro (requisito 1.3):

1. Tamanho total ≤ limite; decodificação estrita (inclui as regras de forma
   das testemunhas e a validação de `PublicKey`/`Signature`).
2. Valores de output em `1..=MAX_SUPPLY`; soma checada.
3. Sem outpoints repetidos dentro da transação (lição do CVE-2018-17144) e,
   no bloco, entre transações.
4. Existência de cada output gasto no UTXO set.
5. `wallet_id(chave) == wallet_id do output` para cada input; testemunhas
   com `wallet_id` distintos.
6. Soma dos inputs ≥ soma dos outputs.
7. Verificação ML-DSA, uma por testemunha, com cache da mempool (requisito 1.7).

## 7. Versionamento

`version` e os campos `kind` são fechados: valores desconhecidos tornam a
transação ou o bloco inválidos. Não há "qualquer um pode gastar" para tipos
futuros, como o Bitcoin faz com versões de witness desconhecidas. Uma mudança
de formato será um fork explícito, com nova versão e nova regra de ativação.
Isso é mais rígido, mas não deixa fundos em outputs que nós antigos tratam
como livres.

## 8. Entregáveis da implementação

Quando aprovada, a implementação em `itacoin-codec`/`itacoin-transaction` deve
vir com:

1. Vetores dourados: bytes, txid, `witness_hash` e `block_id` de transações e
   blocos de exemplo, gerados uma vez e fixados no repositório.
2. Testes de propriedade: `decode(encode(x)) == x` para todo `x`, e
   `encode(decode(b)) == b` para todo `b` aceito.
3. Testes negativos para cada regra de forma: byte sobrando, contagem zero,
   versão/kind desconhecido, `witness_index` fora de ordem ou com salto,
   valor zero ou acima de `MAX_SUPPLY`, entrada maior que o limite.
4. Alvos de fuzzing `transaction` e `block` em `fuzz/`, com a mesma
   propriedade de ida e volta dos alvos atuais.
5. Novos contextos de hash em `itacoin-crypto` (`witness`, `sighash`,
   `spent-outputs`), com teste de separação de domínio.

## 9. Pontos aprovados

1. **Big-endian e campos de largura fixa**, sem varints.
2. **Uma testemunha por chave** (`witness_index`), ou a forma mais simples de
   uma testemunha por input, que custa 5261 bytes a cada input extra.
3. **Sighash com `chain_id` e `spent_outputs_hash`.**
4. **Dois roots no cabeçalho** (`tx_root` e `witness_root`) ou um root único
   sobre `txid ‖ witness_hash`.
5. **Sem campo de dados livres** (memo/`OP_RETURN`) nesta versão.
6. **Sem `lock_time`** nesta versão. Transações com validade a partir de uma
   altura ou hora exigem uma nova versão de transação.
7. **Valores dos limites** da seção 5, provisórios: dependem do intervalo de bloco.
8. **Versionamento fechado** (seção 7).
