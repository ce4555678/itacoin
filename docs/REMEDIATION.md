# Estado das correções da auditoria

Acompanha os achados de [SECURITY_AUDIT.md](SECURITY_AUDIT.md) (2026-11-22).
O relatório de auditoria é mantido como registro histórico e não é editado.

| ID | Achado | Estado | Onde |
| --- | --- | --- | --- |
| V-01 | Ambiguidade da Merkle tree por duplicação do último nó | **Corrigido**: formato RFC 6962, contextos `v2`; teste de regressão para 1..64 folhas e oráculo recursivo | `itacoin-crypto::merkle_root` |
| V-02 | Assinatura sem separação de domínio | **Corrigido**: `SigningDomain` vira o contexto FIPS 204; teste cross-domain | `itacoin-crypto::{PrivateKey::sign, verify}` |
| V-03 | Assinatura determinística | **Corrigido**: assinatura hedged com CSPRNG do SO | `PrivateKey::sign` |
| V-04 | Substituição/rollback do arquivo de carteira | **Corrigido**: `wallet_id` (ou impressão digital, no v3) e geração autenticados; `decrypt_checked` e `replace` recusam substituição e rollback. O binário `itacoin-wallet` guarda a última geração vista no arquivo de estado e recusa um arquivo mais antigo; quem reverte os dois arquivos juntos ainda passa | `itacoin-wallet` (`ITCW` v2 e v3), `itacoin-wallet-cli` |
| V-05 | Documentação dizia que o cabeçalho era AAD | **Corrigido**: o cabeçalho inteiro agora é AAD; teste altera cada byte | `EncryptedWallet::header` |
| V-06 | Senha e KDF fracos | **Corrigido**: senha de 12 a 1024 bytes; Argon2id 64 MiB/3/4 por padrão, parâmetros autenticados e limitados | `Password`, `KdfParams` |
| V-07 | Segredos residuais em memória | **Corrigido nos binários**: `Password`, `to_seed`, segredo mestre e backup zeroizáveis; `itacoin-node` e `itacoin-wallet` chamam `setrlimit(RLIMIT_CORE, 0)`, `prctl(PR_SET_DUMPABLE, 0)` e `umask(077)` ao iniciar, via `rustix` (sem `unsafe`); o nó nunca carrega chave privada e a carteira só decifra durante a assinatura. Sem `mlock`: o limite padrão de memória travada é menor que os 64 MiB do Argon2id (ver a proposta da carteira) | `itacoin-process`, `itacoin-wallet`, `itacoin-crypto` |
| V-08 | Endereço sem checksum; `wallet_id` aceita bytes arbitrários | **Corrigido**: `Address` Bech32m versionado por rede; `wallet_id` exige `PublicKey` | `itacoin-primitives::Address` |
| V-09 | Entradas sem limite de tamanho | **Corrigido**: `merkle_root` limitado a 2^20 folhas; o codec recusa transações acima de `MAX_TX_BYTES` e blocos acima de `MAX_BLOCK_BYTES` antes de decodificar, e confere cada contagem contra os bytes restantes antes de alocar. Valores fixados pela proposta de consenso: 1 MB e 200 verificações por bloco | `MAX_MERKLE_LEAVES`, `itacoin-codec`, `itacoin-transaction`, `itacoin-blockchain` |
| I-01 | `PublicKey::from_bytes` valida só comprimento | Documentado; prova de posse fica para o consenso | `docs/SECURITY.md` |
| I-02 | Vetores ACVP incompletos | **Corrigido**: `keyGen` (2 casos), `sigGen` determinístico e hedged (30 casos, comparação byte a byte) e `sigVer` (15 casos, 3 válidos e 12 inválidos) de ML-DSA-65, interface `external`/`pure` | `itacoin-crypto::mldsa`, `crates/itacoin-crypto/vectors/` |
| I-03 | Limite de `Amount` não é invariante de suprimento | **Corrigido**: `UtxoSet` mantém o valor total dos UTXOs, atualizado em `u128` e limitado a `MAX_SUPPLY` a cada bloco aplicado e revertido, e `audit()` reconta as moedas. `ChainStore` persiste o estado e o recalcula ao abrir | `itacoin-blockchain::utxo`, `itacoin-storage` |
| I-04 | Sem Git, CI ou detecção de mudanças | **Corrigido**: commit inicial, `detect_changes` funcionando; CI com fmt, Clippy, testes, `cargo audit` e 60 s de fuzzing por alvo | `.github/workflows/ci.yml` |
| I-05 | Duplicação de dependências | Aceito; versões fixadas e monitoradas pelo `cargo audit` | — |
| P-07 | I/O de carteira | **Corrigido**: `0600`, escrita atômica, `fsync` de arquivo e diretório, sem sobrescrita, e lock exclusivo entre processos em `.<nome>.lock` durante `write_new`/`replace` (`WalletError::Locked`). MSRV passou para 1.89 por `File::try_lock` | `itacoin-wallet::storage` |
| P-08 | Encoding de endereço com checksum | **Corrigido** (ver V-08) | — |

## Mudanças incompatíveis

Nada foi lançado, mas estas mudanças alteram valores e APIs da etapa 1:

- Os roots de Merkle mudaram (contextos `v1` → `v2` e novo formato da árvore).
- `merkle_root` retorna `Result`.
- `PrivateKey::sign`, `verify`, `Wallet::sign` e `Wallet::verify` recebem um
  `SigningDomain`. Assinaturas antigas, de contexto vazio, não verificam mais.
- `wallet_id` recebe `&PublicKey`; `Wallet::address` recebe uma `Network` e
  devolve um `Address`; o identificador cru está em `Wallet::wallet_id`.
- `PrivateKey::to_seed` devolve `Zeroizing<[u8; 32]>`.
- `Wallet::encrypt` e `EncryptedWallet::decrypt` recebem `&Password`;
  `encrypt` recebe a geração. Arquivos `ITCW` v1 são rejeitados.

## Fuzzing

`fuzz/` contém alvos `cargo-fuzz` (fora do workspace, exigem nightly) para
`Signature`, `PublicKey`, `EncryptedWallet`, `Address`, `Amount`,
`Transaction`, `Block`, as mensagens de rede (`message`), as requisições e
valores em texto do RPC (`rpc_request`), o backup da carteira
(`wallet_backup`) e a seleção de moedas (`coin_selection`). Cada alvo
exige ausência de panic e ida e volta canônica dos bytes ou do texto aceitos:

```sh
cargo +nightly fuzz run encrypted_wallet -- -max_total_time=60
```

## Próximos passos

1. Pendências do [nó](NODE_PROPOSAL.md#ainda-não-implementado) e da
   [carteira](WALLET_PROPOSAL.md#ainda-não-implementado):
   `testmempoolaccept`, índice de transações, `--reindex`, notificações,
   Stratum, exportação de endereços e pagamentos múltiplos.
2. Pendências da [rede](NETWORK_PROPOSAL.md#ainda-não-implementado): sementes
   DNS, Tor, anúncio do próprio endereço, limite de banda histórico, rede
   simulada e revisão criptográfica do handshake.
3. `ChainStore` mantém todo o UTXO set em memória e guarda todos os blocos;
   cache limitado e poda de testemunhas (requisito 1.9) ficam para depois.
4. Fuzzing contínuo (OSS-Fuzz ou execução longa agendada), além do job curto do CI.
