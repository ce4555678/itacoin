# Auditoria de Segurança Adversarial — ITACOIN

- **Data da auditoria:** 2026-11-22
- **Repositório:** `/home/kadu/projetos/itacoin`
- **Commit auditado:** nenhum — o repositório não possui `HEAD` (branch `master` ainda sem commits; todos os arquivos estão untracked)
- **Índice GitNexus:** `itacoin`, reindexado ao final da auditoria (315 nós, 535 arestas, 27 fluxos, 9 clusters); antes da inclusão deste relatório o índice tinha 20 arquivos, 222 nós, 428 arestas e 20 fluxos; `lastCommit` vazio
- **Natureza:** auditoria somente leitura. Nenhum arquivo de código-fonte foi alterado durante a análise.
- **Veredito resumido:** `AUDITORIA INCOMPLETA` para as bibliotecas da etapa 1; `NÃO APTO PARA TESTNET PÚBLICA` para o projeto como um todo.

---

## 1. Resumo executivo

O workspace ITACOIN contém **apenas a etapa 1**: tipos monetários, hashing BLAKE3 com separação de domínio, ML-DSA-65 e uma carteira local criptografada em memória. **Não existem** transações, UTXO, blocos, Proof of Work, armazenamento RocksDB, rede libp2p, runtime Tokio, API Axum, política de emissão implementada nem serialização canônica de protocolo. Os nove diretórios reservados a esses componentes contêm somente um `README.md` cada.

Resultados objetivos:

- 13 testes automatizados passam; `cargo clippy -D warnings` e `cargo fmt --check` estão limpos.
- Nenhum advisory conhecido nas 14 dependências principais consultadas no OSV.
- A análise de grafo (GitNexus) não encontrou ciclos de importação (`check`: `clean`, 0 ciclos).
- **1 vulnerabilidade HIGH**, **3 MEDIUM**, **5 LOW** e **5 INFO** foram identificadas no código existente.
- A ambiguidade estrutural da Merkle tree foi **comprovada experimentalmente**: listas de folhas diferentes produzem o mesmo root. Isso é um vetor de divergência de consenso para a etapa futura.
- A carteira rejeita senha errada, ciphertext adulterado e splice de ciphertext entre arquivos, mas **aceita substituição/rollback do arquivo inteiro**, pois não há vínculo autenticado com a identidade da carteira.
- A assinatura usa ML-DSA-65 puro com **contexto vazio** e não há separação de domínio de assinatura na API. Hoje não há transação; é uma decisão que precisa ser fechada antes do consenso.
- A política de emissão continua sendo **proposta não aprovada**. A soma da proposta foi verificada e fecha exatamente em 10^16 satoshis, mas nada no código a impõe.

As garantias centrais de uma blockchain — ausência de double spend, conservação de valor, emissão limitada, validade de bloco, determinismo entre nós e recuperação após falha — **não podem ser comprovadas**, porque os componentes que as implementariam não existem.

---

## 2. Escopo da auditoria

### 2.1 Incluído

- `crates/itacoin-primitives/src/lib.rs` (319 linhas)
- `crates/itacoin-crypto/src/lib.rs` (464 linhas)
- `crates/itacoin-wallet/src/lib.rs` (330 linhas)
- `Cargo.toml`, `Cargo.lock`, metadados dos três crates
- `README.md`, `docs/SECURITY.md`, `docs/EMISSION_PROPOSAL.md`
- Dependências diretas e transitivas relevantes do `Cargo.lock`
- Harness adversarial externo em `/tmp/opencode/audit-probe` (não faz parte do repositório)

### 2.2 Fora do escopo por ausência de implementação

`itacoin-codec`, `itacoin-transaction`, `itacoin-blockchain`, `itacoin-consensus`, `itacoin-storage`, `itacoin-network`, `itacoin-miner`, `itacoin-rpc` e `itacoin-node`. Esses diretórios contêm apenas `README.md` com o texto “Reserved for a later stage”.

### 2.3 Fora do escopo por decisão do projeto

Contratos inteligentes, hardware wallet, frase mnemônica de recuperação, integração com exchanges e bridge.

---

## 3. Arquitetura efetivamente encontrada

```
itacoin-primitives
  Amount (u64, cap MAX_SUPPLY = 10^16 satoshis)
  Hash256, BlockId, TransactionId, WalletId

itacoin-crypto
  BLAKE3-256 em modo derive_key, contextos versionados
  Merkle tree binária com duplicação do último nó ímpar
  ML-DSA-65 puro (FIPS 204), contexto vazio
  PublicKey / Signature / PrivateKey(seed 32 B) / KeyPair
  verify() de assinaturas

itacoin-wallet
  Wallet em memória (PrivateKey + PublicKey)
  EncryptedWallet (ITCW v1: magic || versão || salt || nonce || ciphertext+tag)
  Argon2id (19 MiB, t=2, p=1) + XChaCha20-Poly1305
```

Grafo de dependências confirmado pelo GitNexus: `itacoin-wallet` → `itacoin-crypto` → `itacoin-primitives`. Não há uso de `std::fs`, `tokio`, `libp2p`, `rocksdb` ou `axum` em nenhum crate (busca textual confirmada).

### 3.1 O que realmente está implementado

| Capacidade | Estado |
|---|---|
| Tipos monetários com aritmética checada | Sim |
| Hashes com separação de domínio | Sim |
| Merkle root | Sim (com ambiguidade estrutural) |
| Geração/assinatura/verificação ML-DSA-65 | Sim |
| Vetores oficiais ACVP | Apenas keygen, 2 casos |
| Carteira em memória | Sim |
| Formato de arquivo criptografado | Sim (serialização pura) |
| Leitura/escrita de arquivo, permissões, atomicidade | **Não** |
| Transação, UTXO, bloco, PoW, emissão | **Não** |
| Rede, storage, RPC, nó | **Não** |

---

## 4. Superfície de ataque

### 4.1 Superfície existente hoje

| Entrada não confiável | Parser | Limite observado |
|---|---|---|
| Chave pública ML-DSA-65 | `PublicKey::from_bytes` | exige 1952 bytes; qualquer conteúdo é aceito |
| Assinatura ML-DSA-65 | `Signature::from_bytes` | exige 3309 bytes; encoding validado |
| Seed privada | `PrivateKey::from_seed` | exige 32 bytes; qualquer seed é válida |
| Arquivo de carteira | `EncryptedWallet::from_bytes` | exige 93 bytes, magic `ITCW`, versão 1 |
| Senha | `Wallet::encrypt` / `decrypt` | apenas não vazia; comprimento ilimitado |
| Bytes de bloco/transação | `block_hash` / `transaction_hash` | comprimento ilimitado |
| Folhas Merkle | `merkle_root` | contagem ilimitada |
| Rótulo/dados internos | `internal_hash` | comprimento ilimitado |

### 4.2 Fronteiras de confiança

1. **Processo local ↔ arquivo de carteira:** o arquivo é tratado como não confiável para confidencialidade/integridade, mas não há vínculo de identidade nem proteção contra rollback.
2. **Processo local ↔ rede (futura):** ainda inexistente. Os parsers de chave/assinatura serão a fronteira quando existir.
3. **Consenso (futuro):** `block_hash`, `transaction_hash` e `merkle_root` recebem bytes crus; a canonicalidade é responsabilidade do chamador, que ainda não existe.

### 4.3 Superfície ausente que será crítica

Rede P2P, RPC, armazenamento em disco, aplicação de blocos, reorg, coinbase, ajuste de dificuldade, UTXO set e serialização canônica. A auditoria não pode avaliar o que não existe.

---

## 5. Metodologia

1. Inventário completo do repositório e identificação do que compila de fato.
2. Revisão manual linha a linha dos três crates.
3. Análise de grafo com GitNexus: `list_repos`, `query`, `context`, `impact`, `check`, `explain`, `detect_changes`.
4. Verificação de alegações da documentação contra o código.
5. Execução de testes, Clippy, rustfmt e análise de dependências.
6. Consulta de advisories no OSV por crate/versão.
7. Harness adversarial em `/tmp/opencode/audit-probe` para Merkle, assinaturas, parsers e carteira.
8. Inspeção do código-fonte das dependências críticas (`ml-dsa` 0.1.2, `module-lattice` 0.2.4, `crypto-common` 0.2.2, `chacha20poly1305` 0.10.1) para confirmar RNG, zeroização e canonicalidade.
9. Classificação de severidade com pré-condições e impacto explícitos.
10. Nenhuma correção foi aplicada.

### 5.1 Resultados do GitNexus

| Consulta | Resultado |
|---|---|
| `list_repos` | `itacoin`: 20 arquivos, 222 nós, 428 arestas, 20 processos, `lastCommit: ""`, staleness `unknown` (estado anterior à inclusão deste relatório; reindexação final: 315 nós, 535 arestas, 27 fluxos) |
| `query("merkle hashing signature wallet encryption consensus")` | retornou `merkle_root`, `Hash256`, arquivos dos três crates e processos de carteira |
| `context(merkle_root)` | chamado apenas por `hash_parts`; **nenhum chamador de produção** |
| `context(hash_parts)` | chamado por `block_hash`, `transaction_hash`, `wallet_id`, `internal_hash`, `merkle_root` |
| `context(Wallet.encrypt)` | 8 processos de carteira; usa `to_seed`, `derive_key`, `validate_password` |
| `impact(PrivateKey.sign, upstream)` | **risk HIGH**, 4 símbolos impactados, 3 fluxos afetados (`Wallet.sign` e testes) |
| `impact(merkle_root, upstream)` | `impactedCount: 0`, **risk UNKNOWN** |
| `impact(EncryptedWallet.from_bytes, upstream)` | risk LOW, 2 chamadores (testes) |
| `impact(Amount.from_itc_str, upstream)` | risk LOW, 1 chamador (`FromStr`) |
| `check(cycles)` | `status: clean`, 0 ciclos |
| `explain()` | sem camada de taint (`analyze --pdg` não executado) |
| `detect_changes(all)` | falhou: `HEAD` inexistente (repositório sem commits) |

**Tratamento do `risk: UNKNOWN`:** conforme a política do projeto, `UNKNOWN` não foi tratado como seguro. A busca textual confirmou que `merkle_root` é usado hoje somente em testes (`crates/itacoin-crypto/src/lib.rs:372-380`), mas é uma API pública exportada e será consumida pelo consenso futuro. O risco de projeto permanece.

**Limitação do GitNexus:** `explain` não encontrou taint porque o índice não foi gerado com `--pdg`; `detect_changes` não funciona sem commit inicial. Essas lacunas estão registradas na seção 19.

---

## 6. Ferramentas executadas

| Ferramenta | Comando | Resultado |
|---|---|---|
| Testes | `cargo test --workspace --all-targets` | 13 passaram, 0 falharam |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | limpo |
| rustfmt | `cargo fmt --all -- --check` | limpo |
| Árvore de dependências | `cargo tree -d` | 4 duplicatas de versão (ver seção 9) |
| OSV | consulta `POST https://api.osv.dev/v1/query` | 0 advisories nas 14 dependências principais |
| GitNexus | `list_repos`, `query`, `context`, `impact`, `check`, `explain`, `detect_changes` | seção 5.1 |
| Harness adversarial | binário Rust externo em `/tmp/opencode/audit-probe` | seção 8 |

### 6.1 Ferramentas indisponíveis

| Ferramenta | Estado | Como executar |
|---|---|---|
| `cargo-audit` | não instalado | `cargo install cargo-audit && cargo audit` |
| `cargo-deny` | não instalado | `cargo install cargo-deny && cargo deny check` |
| `cargo-fuzz` | não instalado | `cargo install cargo-fuzz` + alvos para `Signature`, `PublicKey`, `EncryptedWallet`, codec futuro |
| Miri | não instalado | `rustup component add miri && cargo +nightly miri test` |
| Sanitizers | não configurados | `RUSTFLAGS="-Zsanitizer=address"` em nightly |
| Cobertura | não configurada | `cargo llvm-cov` |

**Nenhum resultado foi inventado.** As ferramentas acima não foram executadas.

---

## 7. Vulnerabilidades encontradas

### Resumo por severidade

| Severidade | Quantidade | IDs |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 1 | V-01 |
| MEDIUM | 3 | V-02, V-04, V-06 |
| LOW | 5 | V-03, V-05, V-07, V-08, V-09 |
| INFO | 5 | I-01 a I-05 |

> Nenhuma vulnerabilidade CRITICAL foi confirmada porque não existe código de consenso que crie moedas ou mova fundos. V-01 é classificada HIGH no estado atual e se torna CRITICAL quando o consenso commitar apenas o Merkle root e aceitar transações duplicadas.

---

### V-01 — Ambiguidade estrutural da Merkle tree por duplicação do último nó

- **Severidade:** HIGH (potencial CRITICAL no consenso futuro)
- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:65-93`, especialmente `:76-79`
- **Componente afetado:** `merkle_root` / árvore de Merkle de transações
- **Descrição técnica:** para nível ímpar, o último nó é duplicado antes do par. Isso faz com que a lista `[a, b, c]` e a lista `[a, b, c, c]` produzam o mesmo root. O mesmo vale para qualquer lista ímpar estendida com uma cópia da última folha. É o análogo estrutural do CVE-2012-2459. A função não commita a contagem de folhas nem rejeita duplicatas.
- **Pré-condições:** (a) o consenso futuro commitar apenas o Merkle root no header; (b) o nó aceitar uma transação duplicada ou não deduplicar o corpo do bloco; (c) o atacante conseguir montar um corpo alternativo com a última transação repetida.
- **Cenário de exploração:** um bloco válido com 3 transações tem root `R`. O atacante propaga um bloco com as mesmas 3 transações e uma quarta cópia da última. O header é idêntico, portanto o `BlockId` é idêntico. Nós que deduplicam rejeitam o corpo; nós que não deduplicam aceitam. O mesmo `BlockId` passa a identificar dois conteúdos diferentes, permitindo divergência de estado, mutabilidade de bloco e confusão em reorg.
- **Evidência reproduzível:**
  ```text
  merkle[3] == merkle[3+dup_last]: true
  merkle[5] == merkle[5+dup_last]: true
  odd-size leaf lists colliding with dup-last extension (n=1..32): 15
  ```
  Os 15 casos são exatamente os tamanhos ímpares de 3 a 31. `n=1` não colide porque não há duplicação.
- **Impacto:** quebra fundamental do vínculo “identificador de bloco ↔ conteúdo do bloco”; divergência de consenso; risco de aceitar corpos distintos sob o mesmo header. Não explorável hoje porque não há blocos.
- **Recomendação de correção:** usar árvore sem duplicação (RFC 6962) ou commitar `leaf_count` no header e rejeitar transações duplicadas no bloco; idealmente ambos. Documentar a regra como parte do consenso e congelar o domínio.
- **Teste de regressão necessário:** propriedade `merkle_root(lista) != merkle_root(lista + [última])` para todo tamanho ímpar; teste de bloco com transação duplicada rejeitado; teste de que `leaf_count` faz parte do header assinado/hasheado.

---

### V-02 — Ausência de separação de domínio nas assinaturas

- **Severidade:** MEDIUM
- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:239-242` e `:280-290`; `crates/itacoin-wallet/src/lib.rs:74-76`
- **Componente afetado:** `PrivateKey::sign`, `Wallet::sign`, `verify`
- **Descrição técnica:** `Signer::sign` do `ml-dsa` usa ML-DSA-65 puro com **contexto FIPS 204 vazio** e assina os bytes exatos recebidos. A API não oferece uma função tipada “assinar transação” com domínio ITACOIN e não impede que a mesma chave assine mensagens arbitrárias. Uma assinatura válida sobre uma mensagem `M` é válida em qualquer contexto que interprete `M` como autorização.
- **Pré-condições:** o protocolo futuro definir dois tipos de mensagem assinada cuja codificação de bytes possa coincidir, ou expor assinatura de mensagens ao usuário (prova de posse, login, etc.).
- **Cenário de exploração:** o usuário assina uma “prova de titularidade” ou mensagem de suporte cujos bytes coincidem com o payload de autorização de uma transação. A assinatura é reutilizada para mover fundos.
- **Evidência reproduzível:** o harness confirma que a mesma assinatura sobre bytes crus verifica sem qualquer contexto; o código de `verify` não recebe nem exige domínio. `crates/itacoin-crypto/src/lib.rs:280-290`.
- **Impacto:** movimentação não autorizada de fundos em versões futuras do protocolo; replay entre domínios.
- **Recomendação de correção:** criar API de assinatura específica de transação usando o parâmetro de contexto do FIPS 204 (ex.: `ITACOIN:tx:v1`) ou assinar `H(domínio || txid)`; nunca expor `sign` cru para uso de consenso. Documentar que assinatura de mensagens usa domínio distinto.
- **Teste de regressão necessário:** assinatura de transação não verifica sob o contexto de mensagem e vice-versa; teste de replay cross-domain rejeitado.

---

### V-03 — Assinatura determinística (não hedged)

- **Severidade:** LOW
- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:239-242`
- **Componente afetado:** `PrivateKey::sign`
- **Descrição técnica:** o `Signer` do `ml-dsa` 0.1.2 usa a variante determinística (`raw_sign_deterministic`, `rnd = 0`). Duas assinaturas da mesma mensagem são byte a byte idênticas. FIPS 204 permite, mas a variante determinística é mais sensível a ataques de injeção de falha e a vazamentos por nonce em implementações defeituosas.
- **Pré-condições:** capacidade de induzir falha física/energética no dispositivo durante a assinatura, ou implementação com bug de nonce.
- **Cenário de exploração:** assinatura defeituosa sob falha induzida pode permitir recuperação de chave em variantes determinísticas; não é ataque remoto.
- **Evidência reproduzível:** `sign deterministic: true` no harness.
- **Impacto:** risco físico/lateral, não remoto; reduz a defesa em profundidade.
- **Recomendação de correção:** usar `sign_randomized` com CSPRNG do SO ou documentar formalmente a escolha e o modelo de ameaça.
- **Teste de regressão necessário:** se randomizado, duas assinaturas da mesma mensagem diferem e ambas verificam.

---

### V-04 — Substituição/rollback do arquivo de carteira não é detectável

- **Severidade:** MEDIUM
- **Arquivo e linha:** `crates/itacoin-wallet/src/lib.rs:26` (AAD constante), `:101-108` (cifragem), `:174-192` (`from_bytes`)
- **Componente afetado:** `EncryptedWallet`
- **Descrição técnica:** o AAD é a constante `ITACOIN:encrypted-wallet:v1`. Ele não inclui o header serializado, o `WalletId`, um contador de geração nem um checksum do arquivo. O formato valida magic, versão e comprimento, mas não vincula o arquivo à identidade da carteira. Substituir o arquivo inteiro por outro arquivo válido é aceito; um rollback para um backup antigo também é aceito silenciosamente.
- **Pré-condições:** acesso de escrita ao arquivo/diretório de backup, ou capacidade de induzir o usuário a restaurar um backup antigo.
- **Cenário de exploração:** (a) rollback: o atacante repõe um backup antigo da mesma carteira; o usuário passa a assinar com uma chave anterior e perde acesso a UTXOs recebidos no endereço novo. (b) substituição: se o atacante possui outro arquivo cifrado com a mesma senha (ou controla a senha), troca o arquivo; o usuário restaura outra identidade sem perceber.
- **Evidência reproduzível:**
  ```text
  spliced ciphertext under foreign salt/nonce decrypts: false
  whole-file substitution yields different wallet: true
  ```
  O splice é corretamente rejeitado; a substituição do arquivo inteiro é aceita.
- **Impacto:** perda de acesso a fundos, confusão de endereço, assinatura com chave errada; não há roubo direto sem a senha, mas há perda econômica.
- **Recomendação de correção:** incluir metadados autenticados no AEAD (versão, `WalletId` esperado, contador de geração), exigir confirmação externa do endereço ao restaurar e definir política de anti-rollback. Alternativamente, usar um MAC separado sobre `magic || versão || salt || nonce || WalletId`.
- **Teste de regressão necessário:** arquivo de A trocado por arquivo de B deve produzir erro de identidade; rollback para geração anterior deve ser detectado quando a política exigir.

---

### V-05 — Documentação afirma que o header é AAD, mas o código usa uma constante

- **Severidade:** LOW
- **Arquivo e linha:** `docs/SECURITY.md:59` versus `crates/itacoin-wallet/src/lib.rs:26`
- **Componente afetado:** documentação de segurança / `EncryptedWallet`
- **Descrição técnica:** a documentação diz que “o cabeçalho de domínio/versionamento é usado como dados autenticados”. O código autentica apenas a constante `ITACOIN:encrypted-wallet:v1`; os bytes reais de magic, versão, salt e nonce não entram no AAD. Não há exploit atual porque magic/versão são pinados em `from_bytes` e salt/nonce são entradas criptográficas, mas a afirmação é falsa.
- **Pré-condições:** nenhuma para o impacto atual; risco de decisões futuras incorretas.
- **Cenário de exploração:** não demonstrado. O risco é de governança: uma mudança futura pode confiar na suposta autenticação do header.
- **Evidência reproduzível:** comparação direta entre `ASSOCIATED_DATA` (`wallet/src/lib.rs:26`) e o texto de `docs/SECURITY.md:59`.
- **Impacto:** baixo hoje; potencial de integridade não intencional no futuro.
- **Recomendação de correção:** corrigir a documentação ou, preferencialmente, autenticar de fato `magic || versão || salt || nonce || WalletId`.
- **Teste de regressão necessário:** teste que altera o byte de versão/magic e exige falha de autenticação (não apenas de formato).

---

### V-06 — Política de senha e parâmetros de KDF insuficientes para ataque offline

- **Severidade:** MEDIUM
- **Arquivo e linha:** `crates/itacoin-wallet/src/lib.rs:201-207` (`validate_password`) e `:209-223` (`derive_key`, parâmetros em `:215`)
- **Componente afetado:** `Wallet::encrypt`, `EncryptedWallet::decrypt`
- **Descrição técnica:** a única regra é senha não vazia. Argon2id usa 19 MiB, 2 iterações e 1 lane (mínimo OWASP, mas modesto para 2026). Não há limite de tentativas, política de força, salt pepper, nem fator de custo variável. O arquivo permite ataque offline ilimitado assim que é roubado.
- **Pré-condições:** roubo/cópia do arquivo `ITCW` e senha fraca ou reutilizada.
- **Cenário de exploração:** o atacante extrai salt e ciphertext e roda Argon2id em GPU/ASIC; senhas curtas ou comuns são recuperadas. Não é necessário interagir com o dono.
- **Evidência reproduzível:** inspeção de `validate_password` e `derive_key`; o harness confirma que a senha é o único segredo adicional.
- **Impacto:** comprometimento total da chave privada e dos fundos associados.
- **Recomendação de correção:** exigir comprimento/entropia mínima, documentar o modelo de ameaça, considerar aumento do custo do Argon2id com versionamento do formato, e oferecer orientação de senha forte/gerenciador de senhas.
- **Teste de regressão necessário:** rejeição de senhas abaixo da política; teste de compatibilidade de parâmetros por versão.

---

### V-07 — Segredos residuais em memória e exposição local

- **Severidade:** LOW
- **Arquivo e linha:** `crates/itacoin-wallet/src/lib.rs:91-159`; `crates/itacoin-crypto/src/lib.rs:228-230`
- **Componente afetado:** manuseio de senha/seed
- **Descrição técnica:** a senha é recebida como `&[u8]` do chamador e não pode ser zeroizada pela biblioteca. `PrivateKey::to_seed` devolve uma cópia crua de 32 bytes. Não há `mlock`, desabilitação de core dump, proteção contra swap ou limite de cópias. `zeroize` cobre a `PrivateKey`, o buffer do Argon2id, o plaintext do AEAD e a chave interna do XChaCha20-Poly1305 (verificado no código da dependência), mas não elimina cópias do compilador/SO.
- **Pré-condições:** acesso local ao processo, core dump, swap ou depurador.
- **Cenário de exploração:** extração de seed de memória após uso da carteira; não é remoto.
- **Evidência reproduzível:** inspeção do código; não há `mlock`/`MADV_DONTDUMP` no repositório.
- **Impacto:** comprometimento local da chave; defesa em profundidade incompleta.
- **Recomendação de correção:** introduzir tipo `SecretBytes` com `Zeroize` e API que receba senha em buffer zeroizável; documentar riscos de swap/core dump; considerar `mlock` em plataformas suportadas.
- **Teste de regressão necessário:** teste de que buffers temporários são zeroizados nos caminhos de erro e sucesso.

---

### V-08 — Endereço sem checksum/encoding e `wallet_id` sem validação de chave

- **Severidade:** LOW
- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:44-48`; `crates/itacoin-primitives/src/lib.rs:265`
- **Componente afetado:** `wallet_id` / `WalletId` / endereço
- **Descrição técnica:** `wallet_id` é BLAKE3 de qualquer slice, sem exigir 1952 bytes nem decodificar uma chave. `WalletId` é um hash de 32 bytes sem checksum, versão ou prefixo legível. Qualquer erro de digitação produz um endereço sintaticamente válido.
- **Pré-condições:** usuário digita/cola endereço; integração futura usa `wallet_id` como identidade.
- **Cenário de exploração:** erro de digitação ou troca de endereço não é detectado; envio para endereço sem chave conhecida (burn).
- **Evidência reproduzível:** `wallet_id(b"anything")` gera um endereço válido; `PublicKey::from_bytes` aceita qualquer sequência de 1952 bytes (2000/2000 no harness).
- **Impacto:** perda de fundos por erro de endereço; ambiguidade de identidade.
- **Recomendação de correção:** definir encoding de endereço com checksum e versão (ex.: Bech32m/HRP `itc`), validar comprimento e decodificação da chave antes de derivar identidade, e documentar que o endereço não substitui a chave pública na verificação.
- **Teste de regressão necessário:** endereço com checksum inválido rejeitado; `wallet_id` de entrada inválida rejeitado ou explicitamente separado da API de endereço.

---

### V-09 — Entradas sem limite de tamanho nas APIs de hash e Merkle

- **Severidade:** LOW
- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:34-42` e `:65-93`
- **Componente afetado:** `block_hash`, `transaction_hash`, `internal_hash`, `merkle_root`
- **Descrição técnica:** as funções aceitam slices e contagens de folhas arbitrárias. `merkle_root` aloca um `Vec` por nível e realoca a cada iteração. Não há limite de profundidade, contagem de folhas ou tamanho de entrada.
- **Pré-condições:** exposição futura dessas funções a dados de rede sem limites no chamador.
- **Cenário de exploração:** bloco/mensagem gigante consome memória/CPU antes da validação; DoS de nó.
- **Evidência reproduzível:** assinaturas das funções não têm parâmetro de limite; implementação de `merkle_root` em `:70-90`.
- **Impacto:** DoS de memória/CPU no futuro nó; hoje apenas uso local.
- **Recomendação de correção:** impor limites no codec/consenso (tamanho máximo de bloco, número máximo de transações, profundidade máxima) e rejeitar entradas acima do limite antes do hashing/da árvore.
- **Teste de regressão necessário:** teste com contagem/tamanho acima do limite retornando erro determinístico.

---

### INFO

#### I-01 — `PublicKey::from_bytes` valida apenas comprimento

- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:111-120`
- **Observação:** 2000/2000 chaves aleatórias de 1952 bytes foram aceitas. Isso é **esperado** pelo encoding ML-DSA-65 (`rho` de 32 bytes + `t1` de 10 bits por coeficiente, todos os padrões válidos), não é falha criptográfica. Porém, `InvalidPublicKey` é efetivamente inalcançável e a API não prova posse da chave. Não trate “chave parseada” como “chave válida para receber fundos”.
- **Recomendação:** documentar e, no consenso, exigir assinatura/Prova de Posse ao vincular uma chave a um endereço.

#### I-02 — Cobertura criptográfica e auditoria independente incompletas

- **Arquivo e linha:** `crates/itacoin-crypto/src/lib.rs:429-463`; `docs/SECURITY.md:20-30`
- **Observação:** apenas 2 vetores ACVP de **keygen** (tc 26 e 27). Não há vetores ACVP de `sig-gen`/`sig-ver`, testes multi-implementação nem fuzzing. O próprio `ml-dsa` 0.1.2 declara não ter auditoria independente.
- **Recomendação:** adicionar vetores completos, fuzzing e revisão criptográfica externa antes de qualquer testnet pública.

#### I-03 — O limite de `Amount` não é uma invariante de suprimento

- **Arquivo e linha:** `crates/itacoin-primitives/src/lib.rs:11-12`, `:26-32`, `:49-56`
- **Observação:** `Amount` limita valores individuais e somas pairwise a `MAX_SUPPLY`, mas não existe contabilidade de emissão acumulada nem soma global de UTXOs. Vários UTXOs, cada um dentro do limite, podem somar acima de 100 milhões se o consenso não impuser conservação. A invariante precisa ser implementada no estado, não apenas no tipo.

#### I-04 — Sem histórico Git, CI ou detecção de mudanças

- **Observação:** o repositório não tem `HEAD`; `git log` falha e `detect_changes` do GitNexus não funciona. Não há workflow de CI, `cargo-audit`, `cargo-deny` ou política de atualização de dependências. Os números do índice antes da reindexação (222 nós/428 arestas) diferem dos citados em `AGENTS.md` (210/418); o índice foi reindexado ao final desta auditoria (315 nós/535 arestas/27 fluxos), mas continua sem `HEAD` para análise de mudanças.
- **Recomendação:** criar commit inicial, CI com testes/Clippy/fmt/audit/deny e reindexar o GitNexus após cada mudança relevante.

#### I-05 — Duplicação de dependências e pinagem exata

- **Arquivo e linha:** `Cargo.toml:20-26`
- **Observação:** `cargo tree -d` mostra `crypto-common` 0.1.7/0.2.2, `digest` 0.10.7/0.11.3, `getrandom` 0.2.17/0.4.3 e `rand_core` 0.6.4/0.10.1. As versões são pinadas com `=` para as primitivas, o que é bom para reprodutibilidade, mas exige monitoramento manual de patches de segurança.

---

## 8. Testes adversariais realizados

### 8.1 Mapa dos 18 cenários solicitados

| # | Cenário | Status | Evidência |
|---|---|---|---|
| 1 | Transação com valor acima do permitido | N/A | Não existe transação; `Amount::from_satoshis` rejeita > `MAX_SUPPLY` |
| 2 | Gastar o mesmo UTXO duas vezes | N/A | Não existe UTXO |
| 3 | Modificar transação após assinatura | Parcial | Mensagem alterada é rejeitada; não há transação |
| 4 | Assinatura inválida | Executado | `verify` rejeita chave errada/mensagem alterada; 200/200 mutações de 1 bit rejeitadas |
| 5 | Chave pública malformada | Executado | Comprimento errado rejeitado; 1952 bytes aleatórios são encoding válido por definição (I-01) |
| 6 | Bloco com recompensa acima do permitido | N/A | Não existe bloco/coinbase |
| 7 | Bloco com PoW inválido | N/A | Não existe PoW |
| 8 | Manipular timestamps | N/A | Não existe header/timestamp |
| 9 | Overflow em cálculos monetários | Executado | `checked_add`/`checked_sub`/`from_whole_itc`/`from_itc_str` |
| 10 | Corromper arquivos da carteira | Executado | Magic/versão/comprimento/tag rejeitados |
| 11 | Recuperar carteira com senha incorreta | Executado | `DecryptionFailed` |
| 12 | Adulterar dados criptografados | Executado | Flip de bit no ciphertext rejeitado; splice entre arquivos rejeitado |
| 13 | Mensagem de rede malformada | N/A | Não existe rede |
| 14 | Mensagem de rede gigante | N/A | Não existe rede |
| 15 | Falha durante gravação no banco | N/A | Não existe banco |
| 16 | Encerramento durante aplicação de blocos | N/A | Não existe aplicação de blocos |
| 17 | Reorganização de cadeia | N/A | Não existe cadeia |
| 18 | Divergência de consenso entre dois nós | N/A (vetor demonstrado) | V-01 mostra que duas listas de folhas diferentes produzem o mesmo root |

### 8.2 Resultados do harness adversarial

Executado em `/tmp/opencode/audit-probe` contra os crates do repositório:

```text
merkle[3] == merkle[3+dup_last]: true
merkle[5] == merkle[5+dup_last]: true
odd-size leaf lists colliding with dup-last extension (n=1..32): 15
sign deterministic: true
same raw message signature verifies (no context enforced): true
random signatures accepted encodings: 0/2000
random pubkeys accepted: 2000/2000
random 32-byte seeds accepted: 2000/2000
valid-format random wallets decrypted: 0/30, panics: 0
spliced ciphertext under foreign salt/nonce decrypts: false
whole-file substitution yields different wallet: true
single-bit message mutations rejected: 176/176
single-bit signature mutations rejected: 200/200
from_itc_str("0.00000000") = Ok(0)
from_itc_str("000001") = Ok(100000000)
from_itc_str("1.0") = Ok(100000000)
from_whole_itc(100000000) = Ok(Amount(10000000000000000))
MAX + 1 sat = Err(ExceedsMaxSupply { satoshis: 10000000000000001 })
```

### 8.3 Interpretação

- **Positivo:** parsers de assinatura, carteira e valores monetários não panicaram e rejeitaram entradas inválidas nos testes realizados.
- **Positivo:** mutações de mensagem e assinatura foram rejeitadas em 100% da amostra.
- **Negativo:** a Merkle tree colide estruturalmente em 15 de 32 tamanhos testados.
- **Negativo:** o arquivo de carteira não tem vínculo de identidade; substituição total é aceita.
- **Atenção:** 2000/2000 chaves públicas aleatórias aceitas não é bug; é consequência do encoding total. Não confunda com validação criptográfica.

### 8.4 O que não foi testado

- Fuzzing real com `cargo-fuzz` (não instalado): apenas amostragem aleatória limitada.
- Miri/sanitizers: não executados.
- Testes multi-nó, reorg, crash-recovery, storage e rede: impossíveis sem implementação.
- ACVP completo de assinatura: não disponível no repositório.

---

## 9. Dependências vulneráveis ou suspeitas

### 9.1 Dependências diretas

| Crate | Versão | Uso | OSV | Observação |
|---|---|---|---|---|
| `blake3` | 1.8.2 | hash | 0 advisories | pino exato |
| `ml-dsa` | 0.1.2 | ML-DSA-65 | 0 advisories | **sem auditoria independente declarada**; pré-1.0 |
| `argon2` | 0.5.3 | KDF | 0 advisories | feature `zeroize` ativa |
| `chacha20poly1305` | 0.10.1 | AEAD | 0 advisories | zeroiza a chave no `Drop` (verificado no código) |
| `zeroize` | 1.8.2 | higiene | 0 advisories | — |
| `rand_core` | 0.6.4 | OsRng | 0 advisories | `getrandom` ativo |

### 9.2 Transitivas relevantes

`module-lattice` 0.2.4, `signature` 3.0.0, `crypto-common` 0.2.2, `chacha20` 0.9.1, `poly1305` 0.8.0, `aead` 0.5.2, `getrandom` 0.2.17/0.4.3 — todas sem advisories no OSV na data da auditoria.

### 9.3 Riscos de supply chain

- `ml-dsa` 0.1.2 é a implementação RustCrypto, mas ainda não auditada de forma independente.
- Versões pinadas com `=` impedem atualizações automáticas de segurança; é necessário monitoramento.
- Duplicação de `crypto-common`, `digest`, `getrandom` e `rand_core` aumenta a superfície de auditoria.
- Não há `Cargo.lock` verificado por CI nem `cargo-deny` para licenças/bans/yanked.
- Licenças declaradas: `Apache-2.0 OR MIT` no workspace; não foi feita verificação arquivo a arquivo das dependências.

**Comandos recomendados:**

```bash
cargo install cargo-audit cargo-deny
cargo audit
cargo deny check advisories bans licenses sources
cargo tree -d
```

---

## 10. Análise criptográfica

### 10.1 BLAKE3-256

| Verificação | Resultado |
|---|---|
| Uso da implementação | `blake3` 1.8.2, sem primitiva própria |
| Modo | `Hasher::new_derive_key(context)` com contexto fixo e versionado |
| Contextos | `itacoin:block:v1`, `itacoin:transaction:v1`, `itacoin:merkle:{empty,leaf,node}:v1`, `itacoin:wallet-id:v1`, `itacoin:internal:v1` |
| Enquadramento | Cada parte é prefixada por `u64` big-endian do comprimento (`crypto/src/lib.rs:95-103`) |
| Ambiguidade de concatenação | Mitigada pelo prefixo de comprimento; teste `internal_hash("a","bc") != internal_hash("ab","c")` |
| Hash truncado | Não há truncamento; saída de 32 bytes |
| Estruturas mutáveis | As entradas são slices; o chamador controla a canonicalidade |
| Verificação de hash recebido | Não existe protocolo/rede; nada a verificar |
| Serialização antes do hash | **Não definida**; `block_hash`/`transaction_hash` recebem bytes crus |
| Compatibilidade com vetores oficiais | BLAKE3 não tem vetores ACVP no repositório; a implementação é a biblioteca upstream |

**Conclusão:** o uso de BLAKE3 está tecnicamente correto e bem domain-separado. A lacuna é a **ausência de uma codificação canônica** de bloco/transação; sem ela, dois nós podem hashear bytes diferentes para o mesmo objeto lógico.

### 10.2 ML-DSA-65

| Verificação | Resultado |
|---|---|
| Conformidade | ML-DSA-65 puro, FIPS 204, contexto vazio, seed de 32 bytes |
| Geração de chaves | `SigningKey::try_generate()` → `crypto-common::Generate::try_generate()` → `SysRng` (getrandom/OS) |
| Aleatoriedade | CSPRNG do SO; falha retorna `KeyGenerationFailed` em vez de chave fraca |
| Assinatura | Determinística (`Signer::sign` do `ml-dsa`), mensagem crua |
| Verificação | `VerifyingKey::verify`, contexto vazio |
| Assinatura inválida | Rejeitada (`VerificationFailed`) |
| Assinatura adulterada | 200/200 mutações de 1 bit rejeitadas |
| Mensagem modificada | 176/176 mutações de 1 bit rejeitadas |
| Chave malformada | Comprimento errado rejeitado; encoding de 1952 bytes é total |
| Tamanhos | PK 1952, assinatura 3309, seed 32 |
| Vetores oficiais | Apenas keygen ACVP tc 26/27; sem sig-gen/sig-ver |
| Tempo constante | Não verificado nesta auditoria; dependência não auditada |
| Serialização/importação | Seed bruta de 32 bytes; sem PKCS#8 no caminho auditado |
| Rotação/revogação | Inexistente |
| Separação de domínio | **Ausente na API** (V-02) |

**Conclusão:** a integração com `ml-dsa` é conservadora e usa a codificação bruta correta. As lacunas são separação de domínio, variante hedged, cobertura de vetores e revisão independente.

### 10.3 Proteção de segredos

| Verificação | Resultado |
|---|---|
| Argon2id | v1.3 (V0x13), 19 MiB, t=2, p=1, saída 32 B |
| Salt | 16 bytes aleatórios por cifragem (`OsRng`) |
| AEAD | XChaCha20-Poly1305, nonce de 24 bytes aleatório por cifragem |
| AAD | Constante `ITACOIN:encrypted-wallet:v1`; não cobre header/identidade (V-04/V-05) |
| Nonce único | 24 bytes aleatórios; probabilidade de colisão desprezível |
| Arquivo adulterado | Rejeitado pela tag |
| Força bruta | Sem limite offline; depende da senha (V-06) |
| Chaves em logs/erros | `Debug` de `PrivateKey` é `PrivateKey(REDACTED)`; erros não incluem segredo |
| zeroize | `PrivateKey`, seed temporária, chave KDF, plaintext AEAD e chave XChaCha (dependência) |
| Limpeza de buffers | Parcial; senha do chamador e cópias do SO não são controladas (V-07) |
| Falha de descriptografia | `DecryptionFailed` uniforme para senha errada e adulteração |

---

## 11. Análise da carteira

### 11.1 Fluxos implementados

- **Criação:** `Wallet::create` → `KeyPair::generate` → `PrivateKey` + `PublicKey`.
- **Importação:** `Wallet::from_private_key(PrivateKey)`; seed de 32 bytes.
- **Endereço:** `WalletId = BLAKE3("itacoin:wallet-id:v1", pk)`.
- **Assinatura:** `Wallet::sign(bytes)` → ML-DSA-65 determinístico, contexto vazio.
- **Verificação:** `Wallet::verify(pk, msg, sig)`.
- **Cifragem:** `Wallet::encrypt(password)` → salt/nonce novos → Argon2id → XChaCha20-Poly1305.
- **Serialização:** `EncryptedWallet::to_bytes` → 93 bytes.
- **Recuperação:** `EncryptedWallet::from_bytes` → `decrypt(password)` → `Wallet`.
- **Armazenamento em disco:** **não implementado**; não há `std::fs`, permissões, escrita atômica, backup ou locking.

### 11.2 Cenários de roubo/adulteração

| Cenário | Resultado |
|---|---|
| Roubo do arquivo `ITCW` | Confidencialidade depende de Argon2id + senha; ataque offline ilimitado (V-06) |
| Senha incorreta | `DecryptionFailed` |
| Ciphertext adulterado | Rejeitado |
| Salt/nonce alterados | Rejeitado (a chave/nonce derivados mudam) |
| Splice de ciphertext entre arquivos | Rejeitado |
| Substituição do arquivo inteiro | **Aceita** (V-04) |
| Rollback para backup antigo | **Aceita silenciosamente** (V-04) |
| Arquivo truncado/estendido | Rejeitado por comprimento exato |
| Magic/versão errados | Rejeitado |
| Arquivo de 93 bytes com salt/nonce/ciphertext aleatórios | 0/30 decifraram; 0 panics |
| Seed de 32 bytes aleatória | Sempre aceita (todo seed é válido) |

### 11.3 Observações

- Não há frase de recuperação; backup = arquivo cifrado + senha. Perder qualquer um torna a chave irrecuperável. Isso está documentado.
- A ausência de I/O de arquivo significa que as garantias de “carteira em disco” (permissões `0600`, escrita atômica, fsync, backup, proteção contra symlink) **não existem**.
- O endereço não tem checksum (V-08).
- A identidade não é autenticada no arquivo (V-04).

---

## 12. Análise do modelo UTXO

**Status: não implementado.** O diretório `crates/itacoin-transaction` contém apenas `README.md`.

Não foi possível verificar nenhum dos itens exigidos:

- double spending;
- inputs inexistentes ou já gastos;
- outputs inválidos/negativos;
- overflow/underflow na soma;
- soma de inputs vs outputs;
- criação indevida de moedas;
- assinatura vinculada ao UTXO correto;
- reutilização/duplicidade de transações;
- identificadores ambíguos;
- validação durante aplicação de blocos;
- consistência após reinício.

A regra fundamental — “nenhuma transação pode criar valor sem autorização explícita das regras de consenso” — **não pode ser comprovada**. O tipo `Amount` impede valores negativos e overflow local, mas não implementa conservação de valor no estado.

---

## 13. Análise do consenso

**Status: não implementado.** `crates/itacoin-consensus` contém apenas `README.md`.

Itens não auditáveis: validação de PoW, comparação hash/target, cálculo e ajuste de dificuldade, timestamps, reorg, cadeias concorrentes, seleção por trabalho acumulado, blocos inválidos/duplicados, recompensa, coinbase, ataques de 51%, races de atualização.

### 13.1 Política de emissão

`docs/EMISSION_PROPOSAL.md` propõe:

```text
E(i) = (1_990_000 - 20_000 × i) × COIN, i = 0..99
Σ E(i) = COIN × (199_000_000 − 99_000_000) = 100_000_000 × COIN = 10^16 satoshis
```

A aritmética foi verificada e fecha exatamente no limite. **Porém:**

- a proposta **não foi aprovada**;
- `N` (blocos por era), intervalo de bloco, gênese, taxas, órfãos e regras de coinbase **não estão definidos**;
- **nenhum código implementa a curva**;
- `MAX_SUPPLY` é apenas um limite de representação em `itacoin-primitives`;
- não há prova de conservação sobre o conjunto de UTXOs.

**Pendência crítica de especificação:** a política de emissão precisa ser aprovada e implementada com aritmética inteira e prova de soma antes de qualquer testnet pública. Nenhuma política foi inventada nesta auditoria.

---

## 14. Análise de armazenamento e rede

### 14.1 Armazenamento

RocksDB **não está implementado**. Não há atomicidade, recuperação após crash, reorg, índices, reindexação, concorrência ou rollback de blocos. A carteira também não grava em disco.

### 14.2 Rede P2P

libp2p **não está implementado**. Não há proteção contra spoofing, Sybil, eclipse, flooding, spam, mensagens malformadas, limites de conexão/tamanho, rate limiting, timeouts, consumo de memória/CPU, propagação de blocos inválidos, transporte seguro ou autenticação de peers.

### 14.3 API

Axum **não está implementado**. Não há endpoints, validação, rate limiting, autorização administrativa, tratamento de erros ou exposição de dados internos.

### 14.4 Observação de arquitetura

Os três componentes acima são os que mais ampliam a superfície de ataque. A auditoria atual não pode avaliar nenhum deles; a etapa 1 é, por construção, local e offline.

---

## 15. Invariantes comprovadas

Com evidência no código/testes/harness:

1. **Valores monetários não negativos e sem overflow local.** `Amount` é `u64`, `checked_add`/`checked_sub`/`from_whole_itc`/`from_itc_str` usam aritmética checada; `MAX + 1` retorna `ExceedsMaxSupply`.
2. **`MAX_SUPPLY` correto.** `100_000_000 × 100_000_000 = 10^16`, que cabe em `u64`.
3. **Separação de domínio de hash.** Contextos distintos para bloco, transação, Merkle (empty/leaf/node), wallet-id e interno.
4. **Enquadramento não ambíguo de partes.** Prefixo `u64` big-endian; teste `("a","bc") != ("ab","c")`.
5. **ML-DSA-65 roundtrip.** Geração, assinatura, verificação e serialização funcionam.
6. **Rejeição de assinatura inválida.** Chave errada, mensagem alterada, assinatura malformada e mutações de 1 bit rejeitadas.
7. **Vetores oficiais de keygen.** 2 casos ACVP ML-DSA-65 (tc 26/27) passam byte a byte via fingerprint BLAKE3.
8. **Carteira rejeita senha errada e adulteração.** `DecryptionFailed` uniforme.
9. **Carteira rejeita splice de ciphertext entre arquivos.**
10. **Salt e nonce novos por cifragem.** Teste `encrypted_wallet_uses_fresh_randomness`.
11. **Chave privada não é imprimível.** `Debug` redigido; `ZeroizeOnDrop`.
12. **Sem `unsafe`.** `unsafe_code = "forbid"` no workspace.
13. **Sem ciclos de importação.** GitNexus `check`: clean, 0 ciclos.
14. **Parsers testados não panicaram** em 2000 assinaturas aleatórias, 2000 pubkeys, 2000 seeds, 30 arquivos de carteira bem formados e 376 mutações de 1 bit (176 de mensagem + 200 de assinatura).

---

## 16. Invariantes não comprovadas

1. Nenhum UTXO pode ser gasto duas vezes. **Sem código de UTXO.**
2. Nenhuma transação inválida entra em bloco válido. **Sem código de transação/bloco.**
3. Nenhuma assinatura inválida autoriza fundos. **Parcial:** verificação criptográfica funciona, mas não há vínculo com UTXO/transação.
4. Nenhum bloco inválido entra na cadeia. **Sem consenso.**
5. Emissão acumulada ≤ 100.000.000 ITC. **Sem consenso nem contabilidade de estado.**
6. Nenhuma operação monetária causa overflow silencioso. **Parcial:** tipo `Amount` é checado, mas não há somas globais.
7. Todos os nós chegam ao mesmo resultado. **Sem codec canônico nem rede.**
8. Estado recuperável após falhas. **Sem storage.**
9. Chaves privadas não são armazenadas em texto puro. **Parcial:** o formato é cifrado, mas não há gravação em disco auditada.
10. A carteira rejeita dados criptográficos adulterados. **Parcial:** rejeita tag/splice; aceita substituição/rollback do arquivo inteiro.
11. Unicidade do Merkle root. **Refutada** (V-01).
12. Resistência a força bruta de senha. **Não comprovada** (V-06).
13. Tempo constante do ML-DSA. **Não verificado.**
14. Liberdade de panics sob fuzzing real. **Não executado.**
15. Endereço sem ambiguidade/erro de digitação. **Não comprovado** (V-08).

---

## 17. Pendências arquiteturais

| ID | Pendência | Severidade de risco | Observação |
|---|---|---|---|
| P-01 | Codec canônico determinístico (endianness, campos, versão, limites) | HIGH | Sem ele, hashes e validação podem divergir entre nós |
| P-02 | Política de emissão aprovada e implementada | CRITICAL (especificação) | Proposta existe; `N`, gênese, taxas e órfãos indefinidos |
| P-03 | UTXO, transações e conservação de valor | CRITICAL | Núcleo da segurança econômica |
| P-04 | PoW, dificuldade, reorg e trabalho acumulado | CRITICAL | Núcleo do consenso |
| P-05 | Storage atômico com rollback/recovery | HIGH | RocksDB nem começou |
| P-06 | Rede P2P e API com threat model | HIGH | Superfície futura |
| P-07 | I/O de carteira (permissões, atomicidade, backup) | MEDIUM | Hoje só serialização em memória |
| P-08 | Encoding de endereço com checksum | MEDIUM | Evita perda por erro de digitação |
| P-09 | Rotação/revogação de chaves | MEDIUM | ML-DSA é longevo; precisa de plano |
| P-10 | Revisão criptográfica independente e interoperabilidade | HIGH | `ml-dsa` não auditado |
| P-11 | Parâmetros concretos de testnet (gênese, faucet, limites) | HIGH | Depende de P-01/P-02 |
| P-12 | CI, `cargo-audit`/`deny`, commit inicial | MEDIUM | Reprodutibilidade e supply chain |

---

## 18. Plano de correção

### Fase 0 — Decisões de especificação (antes de código)

1. Aprovar ou rejeitar a curva de emissão, definindo `N`, gênese, taxas e órfãos (P-02).
2. Congelar a codificação canônica de bloco/transação e o enquadramento de hashes (P-01).
3. Definir a regra de Merkle (RFC 6962 ou `leaf_count` + rejeição de duplicatas) (V-01).
4. Definir domínio de assinatura de transação e de mensagem (V-02).
5. Definir encoding de endereço com checksum (V-08).

### Fase 1 — Criptografia

1. Corrigir a Merkle tree e adicionar testes de unicidade (V-01).
2. Adicionar API de assinatura com domínio e testes cross-domain (V-02).
3. Decidir entre assinatura determinística e hedged; documentar (V-03).
4. Impor limites de tamanho/contagem nas APIs de hash/Merkle (V-09).
5. Adicionar vetores ACVP completos de `sig-gen`/`sig-ver` (I-02).
6. Criar alvos de fuzzing para `PublicKey`, `Signature` e `EncryptedWallet`.

### Fase 2 — Carteira

1. Autenticar metadados (versão + `WalletId` + geração) no arquivo (V-04/V-05).
2. Definir política de senha e revisar custo do Argon2id (V-06).
3. Introduzir tipo de segredo zeroizável e documentar riscos locais (V-07).
4. Implementar I/O seguro: `0600`, escrita atômica, fsync, backup e locking (P-07).
5. Corrigir a documentação de segurança.

### Fase 3 — Codec, transação e UTXO

1. Implementar codec canônico com testes de propriedade e vetores.
2. Implementar transações, assinatura vinculada a UTXO e verificação completa.
3. Implementar UTXO set com conservação de valor e testes de double spend.
4. Provar por soma inteira que a emissão nunca excede `MAX_SUPPLY`.

### Fase 4 — Consenso e storage

1. Implementar PoW, target, dificuldade, timestamps e seleção por trabalho acumulado.
2. Implementar aplicação/rollback atômico de blocos e recuperação após crash.
3. Testar reorg, cadeias concorrentes, blocos duplicados e falhas de escrita.
4. Provar determinismo entre dois nós com o mesmo conjunto de dados.

### Fase 5 — Rede e API

1. Definir threat model de P2P (Sybil/eclipse/flooding/spam).
2. Implementar limites de conexão, tamanho, rate limiting e timeouts.
3. Definir autenticação de peers e transporte seguro.
4. Implementar API com validação, autorização administrativa e limites.

### Fase 6 — Pré-testnet

1. Revisão criptográfica independente.
2. `cargo-audit`/`cargo-deny` limpos.
3. Fuzzing contínuo e Miri/sanitizers.
4. Reindexar GitNexus com `--pdg` e revisar taint.
5. Auditoria externa completa.

---

## 19. Critérios para uma nova auditoria

A nova auditoria só deve começar quando existirem:

- [ ] commit inicial e histórico Git com CI obrigatório;
- [ ] codec canônico congelado e testado com vetores;
- [ ] política de emissão aprovada e implementada com prova de soma;
- [ ] transações/UTXO com testes de double spend e conservação;
- [ ] PoW/reorg/storage com testes de crash e recuperação;
- [ ] Merkle tree sem ambiguidade, com teste de unicidade;
- [ ] separação de domínio de assinatura implementada e testada;
- [ ] carteira com metadados autenticados e I/O seguro;
- [ ] ACVP completo de keygen, sig-gen e sig-ver;
- [ ] fuzzing contínuo de todos os parsers de rede;
- [ ] `cargo-audit` e `cargo-deny` limpos;
- [ ] revisão criptográfica independente do `ml-dsa` ou implementação alternativa validada;
- [ ] threat model documentado para nó, carteira, rede e API;
- [ ] índice GitNexus atualizado com `--pdg` e `detect_changes` funcionando;
- [ ] todas as vulnerabilidades HIGH/MEDIUM corrigidas ou formalmente aceitas com justificativa.

---

## 20. Conclusão sobre a prontidão de segurança

### 20.1 Contagem final

| Severidade | Quantidade |
|---|---|
| CRITICAL | 0 |
| HIGH | 1 |
| MEDIUM | 3 |
| LOW | 5 |
| INFO | 5 |

### 20.2 Componentes mais arriscados

1. **Merkle tree** (`itacoin-crypto`): ambiguidade estrutural comprovada; blocker de consenso.
2. **API de assinatura** (`itacoin-crypto`/`itacoin-wallet`): ausência de domínio; risco de replay.
3. **Arquivo de carteira** (`itacoin-wallet`): substituição/rollback indetectável e KDF dependente de senha fraca.
4. **Especificação de consenso/emissão**: ausente; nenhuma garantia econômica pode ser provada.

### 20.3 Garantias comprovadas

Aritmética monetária local checada, separação de domínio de hash, ML-DSA-65 funcional com rejeição de assinaturas inválidas, keygen conforme 2 vetores ACVP, carteira com AEAD correto contra adulteração/senha errada, salt/nonce frescos, zeroização parcial e ausência de `unsafe`/ciclos.

### 20.4 Garantias que dependem de implementação

Double spend, conservação de valor, limite de emissão no estado, validade de bloco/PoW, determinismo entre nós, atomicidade/recuperação de storage, rate limiting de rede/API, I/O seguro de carteira e encoding de endereço.

### 20.5 Riscos que impedem testnet pública

- V-01 (Merkle) e V-02 (domínio de assinatura) sem correção.
- Ausência total de codec canônico, transações, UTXO, PoW, storage e rede.
- Política de emissão não aprovada.
- `ml-dsa` sem auditoria independente e sem vetores completos.
- Carteira sem vínculo de identidade/anti-rollback e sem I/O seguro.
- Ausência de CI, `cargo-audit`/`deny` e fuzzing.

### 20.6 Riscos que impedem mainnet

Todos os anteriores, mais: prova formal/empírica de conservação de valor, análise de 51%, incentivos econômicos, auditoria externa completa, resposta a incidentes, processo de divulgação responsable, testes multi-implementação, hardening de secrets e plano de rotação/revogação de chaves. **Nenhum teste verde autoriza mainnet.**

### 20.7 Avaliação final

- **Bibliotecas da etapa 1:** `AUDITORIA INCOMPLETA`.
- **Projeto ITACOIN como blockchain:** `NÃO APTO PARA TESTNET PÚBLICA`.
- **Testnet controlada e sem valor:** só é defensável após corrigir V-01 e V-02 e congelar codec/emissão; ainda assim, com ressalvas explícitas.

---

## Apêndice A — Comandos de reprodução

```bash
# Testes e qualidade
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check

# Dependências
cargo tree -d
cargo install cargo-audit cargo-deny
cargo audit
cargo deny check advisories bans licenses sources

# GitNexus (via CLI, quando disponível)
node .gitnexus/run.cjs analyze --index-only
node .gitnexus/run.cjs check --repo .
node .gitnexus/run.cjs impact "PrivateKey::sign" --direction upstream --repo .
node .gitnexus/run.cjs detect-changes --scope all --repo .

# Harness adversarial (externo, não versionado)
cd /tmp/opencode/audit-probe && cargo run --quiet
```

## Apêndice B — Evidências GitNexus

- Repositório indexado: `itacoin`, 20 arquivos, 222 nós, 428 arestas, 20 processos no início da auditoria; 315 nós, 535 arestas e 27 fluxos após a reindexação final (que incluiu este relatório).
- `impact(PrivateKey.sign, upstream)`: `risk: HIGH`, 4 símbolos impactados, 3 fluxos (`Wallet.sign` e testes).
- `impact(merkle_root, upstream)`: `impactedCount: 0`, `risk: UNKNOWN`; busca textual confirma uso apenas em testes.
- `impact(EncryptedWallet.from_bytes, upstream)`: `risk: LOW`, 2 chamadores de teste.
- `impact(Amount.from_itc_str, upstream)`: `risk: LOW`, 1 chamador (`FromStr`).
- `check`: `status: clean`, `cycleCount: 0`.
- `explain`: `totalFindings: 0`, camada de taint ausente.
- `detect_changes`: indisponível por ausência de `HEAD`.

## Apêndice C — Declaração de limitações

Esta auditoria não substitui uma revisão criptográfica independente, não executou fuzzing contínuo, Miri ou sanitizers, não avaliou código inexistente e não testou ambientes de rede. Nenhuma correção foi aplicada. As classificações de severidade assumem o modelo de ameaça descrito nas seções 4 e 11; mudanças nesse modelo exigem reavaliação.