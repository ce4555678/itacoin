# Requisitos para as próximas etapas

Restrições que `itacoin-codec`, `itacoin-transaction`, `itacoin-blockchain`,
`itacoin-consensus`, `itacoin-network` e `itacoin-rpc` devem respeitar. Nada
aqui está implementado ainda; são requisitos de projeto, não regras de
consenso aprovadas.

## 1. Custo das assinaturas pós-quânticas

### Números

| Item | ML-DSA-65 | Referência ECDSA/Schnorr secp256k1 |
| --- | --- | --- |
| Chave pública | 1952 bytes | 33 / 32 bytes |
| Assinatura | 3309 bytes | ~72 / 64 bytes |
| Autorização de um input (chave + assinatura) | **5261 bytes** | ~105 bytes (≈ 50× menor) |
| Assinar | 2,3 ms | — |
| Verificar | 0,35 ms | — |
| Gerar chave | 1,0 ms | — |

Os tempos foram medidos com `ml-dsa` 0.1.2 em build release, em um núcleo de
um Intel Core i5-3570 a 3,4 GHz (2026-11-23), com média de 2000 operações.
Eles são uma ordem de grandeza, não um benchmark de referência.

A conclusão é que **o gargalo é banda e armazenamento, não CPU**. Verificar
um bloco com 1 MB de autorizações (~190 inputs) custa cerca de 67 ms em um
núcleo. Já uma transação de 1 input e 2 outputs ocupa ~5,4 KB: uma média de
uma transação por segundo acumula ~170 GB de cadeia por ano.

### Requisitos

1. **Outputs commitam ao `wallet_id`, nunca à chave pública.** O output
   guarda 32 bytes. A chave de 1952 bytes só aparece quando o output é gasto.
   Assim o UTXO set (que todo nó mantém em disco e cache) não cresce com o
   tamanho das chaves pós-quânticas.
2. **O txid não inclui chaves nem assinaturas.** A assinatura é hedged
   (achado V-03): assinar a mesma transação duas vezes produz bytes
   diferentes. Se a assinatura entrasse no txid, o próprio signatário poderia
   gerar txids diferentes para a mesma transação (maleabilidade), o que
   quebra cadeias de transações não confirmadas. O txid deve cobrir só os
   dados sem testemunha, e a Merkle tree do bloco deve commitar também às
   testemunhas, por um segundo root ou por folhas que incluam o hash da
   testemunha.
3. **Ordem de validação do barato para o caro.** Primeiro limites de tamanho
   e contagem, depois a existência do UTXO, depois
   `wallet_id(chave) == wallet_id do output` (um hash BLAKE3) e, por último,
   a verificação ML-DSA. Uma chave que não corresponde ao output é rejeitada
   sem custo de verificação.
4. **Limites explícitos por bloco**: bytes totais e número de verificações de
   assinatura, ambos regras de consenso. O limite em bytes deve ser
   dimensionado em autorizações de ~5,3 KB, não em transações de 250 bytes.
5. **Taxa por byte sem desconto para testemunha.** As assinaturas são a maior
   parte dos bytes. Descontá-las, como faz o SegWit, tornaria barato justamente
   o que mais pesa na rede e no disco.
6. **Uma assinatura por chave distinta, não por input.** Avaliar na
   especificação: quando vários inputs de uma transação pertencem ao mesmo
   `wallet_id`, uma única chave e uma única assinatura sobre a transação
   inteira podem autorizar todos eles. Isso reduz consolidações em até N×
   5261 bytes.
7. **Cache de verificação.** Assinaturas verificadas na mempool não são
   verificadas de novo quando a transação chega em um bloco.
8. **Rede:** os blocos devem propagar por *compact blocks* (anunciar
   identificadores curtos e transmitir só as transações que o peer não tem),
   e cada mensagem P2P deve ter um tamanho máximo verificado antes de alocar
   o buffer.
9. **Poda de testemunhas.** Nós podem descartar as testemunhas de blocos
   profundamente enterrados, mantendo os roots. Isso só é possível se o
   requisito 2 for respeitado.

## 2. Aritmética monetária e de emissão

### Margens da proposta de emissão

| Valor | Satoshis | Fração de `u64::MAX` (≈ 1,84 × 10^19) |
| --- | --- | --- |
| Maior emissão de era, `E(0)` | 1,99 × 10^14 | 0,001% |
| Soma de todas as eras | 1,0 × 10^16 | 0,054% |

A curva proposta cabe com folga em `u64`. O risco real de overflow está em
outro lugar: **na soma de valores de transações**. Cada `Amount` é no máximo
`MAX_SUPPLY` (10^16), mas uma transação com 2000 inputs declarando esse valor
soma 2 × 10^19, acima de `u64::MAX`. Um atacante controla esses números até
que cada input seja checado contra o UTXO set.

### Requisitos

1. **Consenso nunca faz aritmética monetária com `+`, `-` ou `*`.** Somas de
   inputs, outputs, taxas e recompensas usam `Amount::checked_add` /
   `checked_sub`, que já recusam overflow *e* qualquer total acima de
   `MAX_SUPPLY`. Isso é correto para consenso: nenhum conjunto válido de
   valores excede o suprimento total.
2. **Cálculos intermediários fora de `Amount` usam `u128`** e só voltam para
   `u64` por `u64::try_from`, nunca por `as`. Exemplos: a soma de verificação
   de todas as eras, `recompensa_base × N + extra == E(i)` e somas acumuladas
   de suprimento emitido.
3. **Overflow nunca pode virar panic.** O workspace compila release com
   `overflow-checks = true`. Isso troca um wrap silencioso por um panic, e
   um panic em um nó é uma queda remota (DoS). A verificação de overflow
   existe como rede de segurança; o código de consenso deve devolver erro
   antes de chegar a ela.
4. **A curva de emissão, quando aprovada, deve vir com um teste que soma
   todas as recompensas, bloco a bloco ou era a era em `u128`**, e exige
   igualdade exata com `MAX_SUPPLY`. Esse teste também deve checar que
   `subsidy(altura)` devolve zero para toda altura depois da última era,
   inclusive `u64::MAX`, sem overflow no cálculo `altura / N`.
5. **A recompensa da coinbase é validada como `subsídio + taxas`, ambos
   `Amount`**, e o suprimento acumulado do estado da cadeia (achado I-03) é
   uma invariante checada a cada bloco aplicado e revertido.

## 3. Representação em texto

Em disco e na rede P2P todo valor trafega na codificação binária canônica. As
regras abaixo valem só onde um valor vira texto para pessoas ou para uma API
(RPC, JSON, logs, explorador de blocos).

| Valor | Formato | Exemplo de tamanho |
| --- | --- | --- |
| Hashes e identificadores (`Hash256`, txid, block id, `wallet_id`) | hex minúsculo | 64 caracteres |
| Endereços | Bech32m com prefixo de rede (`Address`) | 63 caracteres |
| Chaves públicas ML-DSA-65 | base64url sem padding (RFC 4648 §5) | 2603 caracteres (hex: 3904) |
| Assinaturas ML-DSA-65 | base64url sem padding | 4412 caracteres (hex: 6618) |
| Transações e blocos serializados | base64url sem padding | ~33% menor que hex |

### Justificativa

- **Hashes ficam em hex.** Base64 economizaria só 21 caracteres por hash, ao
  custo de diferenciar maiúsculas de minúsculas, usar símbolos que quebram a
  seleção por duplo clique e fugir da convenção de toda ferramenta de
  blockchain. Esses valores são comparados e buscados por pessoas.
- **Endereços ficam em Bech32m.** O checksum detecta erros de digitação, e um
  erro não detectado manda fundos para uma chave que ninguém controla. O
  formato não diferencia maiúsculas de minúsculas e, em maiúsculas, usa o
  modo alfanumérico do QR code. Base64 não tem nenhuma dessas propriedades.
- **Blobs grandes usam base64url.** Uma autorização de input (chave e
  assinatura) ocupa ~10,5 KB em hex e ~7 KB em base64url. Esses valores não
  são lidos por pessoas, então a ilegibilidade não custa nada. A variante URL
  (`-` e `_`) dispensa escape em URLs e query strings.

### Requisitos

1. **Decodificação estrita.** Recusar padding, caracteres fora do alfabeto
   base64url, espaços e bits de preenchimento diferentes de zero. Cada valor
   deve ter **uma única** representação em texto aceita. Do contrário, dois
   textos diferentes decodificam para o mesmo valor, e caches ou deduplicação
   por texto divergem.
2. **Hex só minúsculo na saída e recusa de prefixo `0x`.** Na entrada, aceitar
   hex maiúsculo é opcional, mas a forma canônica emitida é sempre minúscula.
3. **Limite de tamanho antes de decodificar.** Uma API calcula o comprimento
   máximo em texto a partir do limite binário (`ceil(4n/3)` para base64url,
   `2n` para hex) e recusa entradas maiores sem alocar o buffer decodificado.
4. **O formato em texto não é consenso.** Hashes, assinaturas e txids são
   sempre calculados sobre os bytes binários, nunca sobre a representação em
   texto.
5. **Implementação.** Usar uma biblioteca com modo estrito (por exemplo,
   `base64` com `URL_SAFE_NO_PAD` e `decode_allow_trailing_bits(false)`), com
   versão fixada como as demais dependências. Não escrever o codificador à
   mão.
