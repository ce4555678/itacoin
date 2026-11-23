# Emissão — aprovada

> Aprovada em 2026-11-23 junto com a [proposta de consenso](CONSENSUS_PROPOSAL.md),
> que fixou `N = 262.800` blocos, o gênese queimado e o destino das taxas.
> Implementada em `itacoin_consensus::subsidy`, com teste que soma todas as
> recompensas e exige igualdade exata com `MAX_SUPPLY`.
>
> O texto abaixo é a proposta original.

> Esta é uma proposta matemática, não uma regra de consenso nem uma política
> econômica aprovada. Nenhum código desta primeira etapa a implementa.

## Curva candidata

Propõe-se uma curva linear decrescente em 100 eras de igual número de blocos.
Seja `i` o índice da era, de 0 a 99. A emissão total da era, em satoshis ITC,
seria:

```text
E(i) = (1_990_000 - 20_000 × i) × COIN
```

Assim, a primeira era emite 1.990.000 ITC e a última 10.000 ITC. Não se cria
moeda nova após a era 99.

O número de blocos por era não é proposto aqui, porque o intervalo de bloco e
o desenho de Proof of Work ainda não foram definidos. Quando esse parâmetro
`N` for aprovado, cada era deve distribuir exatamente seu total com aritmética
inteira:

```text
recompensa_base = E(i) / N
blocos_com_uma_unidade_extra = E(i) % N
```

Os primeiros `blocos_com_uma_unidade_extra` blocos recebem
`recompensa_base + 1`; os demais recebem `recompensa_base`. Isso evita
arredondamento, ponto flutuante e emissão residual.

## Prova do limite

```text
Σ E(i), i = 0..99
= COIN × [100 × 1_990_000 - 20_000 × (99 × 100 / 2)]
= COIN × (199_000_000 - 99_000_000)
= 100_000_000 × COIN
= 10_000_000_000_000_000 satoshis ITC
```

Portanto a soma de todas as recompensas é exatamente o suprimento máximo, sem
dependência de frações ou arredondamento. Taxas de transação, se houver, devem
ser transferidas de transações existentes e não contar como emissão.

## Aritmética

A maior emissão de era, `E(0)`, é 1,99 × 10^14 satoshis, e a soma total é
10^16. As duas cabem em `u64` com folga. Mesmo assim, a implementação deve
somar em `u128` com operações checadas e converter de volta só por
`u64::try_from`. O teste de aprovação da curva deve somar todas as
recompensas e exigir igualdade exata com `MAX_SUPPLY`. Os requisitos completos,
incluindo o risco de overflow nas somas de transações, estão em
[PROTOCOL_REQUIREMENTS.md](PROTOCOL_REQUIREMENTS.md#2-aritmética-monetária-e-de-emissão).

## Pontos que precisam de aprovação

- Duração da era (`N`), intervalo alvo de bloco e duração total da emissão.
- Recompensa do bloco gênese: a recomendação desta proposta é zero, salvo uma
  alocação explícita que seja subtraída das eras sem aumentar o limite.
- Modelo de taxas, política de blocos órfãos e regras completas de coinbase.
- Se a curva linear é economicamente desejável frente a alternativas como uma
  curva escalonada ou exponencial.

Somente após aprovação explícita desses pontos a curva poderá virar uma função
de consenso testada. Até lá, `MAX_SUPPLY` é somente um limite de representação
em `itacoin-primitives`.
