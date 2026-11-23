# Segurança criptográfica — etapa 1

Este documento descreve as escolhas da primeira etapa e seus limites. Ele não é
uma afirmação de que a ITACOIN está pronta para produção. O estado de cada
achado da auditoria está em [REMEDIATION.md](REMEDIATION.md).

## Dependências e compatibilidade

| Componente | Dependência fixada | Uso |
| --- | --- | --- |
| Hash | `blake3` 1.8.2 | BLAKE3-256 para bloco, transação, Merkle, identificador de carteira e dados internos |
| Assinatura | RustCrypto `ml-dsa` 0.1.2 | ML-DSA-65 puro, FIPS 204, hedged, contexto por domínio |
| KDF | RustCrypto `argon2` 0.5.3 | Argon2id para chave de armazenamento local |
| AEAD | RustCrypto `chacha20poly1305` 0.10.1 | XChaCha20-Poly1305 para o seed de carteira |
| Endereço | rust-bitcoin `bech32` 0.11.0 | Bech32m (BIP 350) com checksum |
| Higiene de memória | `zeroize` 1.8.2 | Apagamento por `Drop` da chave privada, da senha e de buffers temporários |

As versões são exatas no `Cargo.toml` e suas versões transitivas ficam em
`Cargo.lock`. Nenhuma primitiva criptográfica é implementada pela ITACOIN.

`ml-dsa` 0.1.2 é a implementação RustCrypto de FIPS 204 final e suporta
ML-DSA-65. A biblioteca declara explicitamente que não recebeu auditoria
independente. Ela é isolada em duas camadas para permitir trocar a
implementação após auditoria e interoperabilidade independentes:

- nenhum tipo do `ml-dsa` aparece na API pública. `PublicKey`, `Signature` e
  `PrivateKey` guardam apenas as codificações FIPS 204 em bytes;
- dentro de `itacoin-crypto`, só o módulo privado `mldsa.rs` chama a
  biblioteca, por funções sobre bytes (`generate_seed`, `public_key`, `sign`,
  `verify` e validações). Um teste falha se `lib.rs` voltar a chamar o
  `ml-dsa` diretamente.

Trocar ou verificar a implementação contra uma segunda (por exemplo, uma
binding auditada) significa reescrever esse único arquivo e passar pelos
mesmos testes, incluindo os vetores ACVP. Não há trait de backend, porque
existe uma só implementação. Se for preciso validar duas implementações em
paralelo, a separação por funções permite introduzir o trait sem mudar a API
pública.
Usar a biblioteca não equivale a uma validação FIPS 140 de um módulo
criptográfico.

Os testes incluem os casos 26 e 27 do grupo ML-DSA-65 dos vetores oficiais
NIST ACVP `ML-DSA-keyGen-FIPS204`. Para manter o repositório pequeno, cada
chave pública oficial de 1952 bytes é comparada por sua impressão BLAKE3-256;
isso exige igualdade byte a byte com a resposta oficial. Ainda faltam testes
ACVP completos de geração e verificação de assinatura antes de qualquer
lançamento.

## Regras de hash

Cada função pública usa `blake3::Hasher::new_derive_key` com um contexto fixo
e versionado, como `itacoin:block:v1` ou `itacoin:wallet-id:v1`. Entradas com
mais de uma parte são prefixadas por comprimentos `u64` big-endian antes do
hash.

A árvore de Merkle (contextos `itacoin:merkle:*:v2`) segue o formato da
RFC 6962: folhas e nós internos usam domínios distintos, e um nó ímpar no fim
de um nível é promovido sem ser duplicado. Assim `[a, b, c]` e `[a, b, c, c]`
têm roots diferentes, o que elimina a ambiguidade da versão 1 (achado V-01). A
função recusa mais de `MAX_MERKLE_LEAVES` (2^20) folhas; esse é um limite de
segurança da API, e o consenso deve impor limites de bloco menores antes de
construir uma árvore a partir de dados não confiáveis.

Os contextos e a serialização canônica de blocos/transações deverão ser
congelados pela especificação de consenso. Alterá-los altera identificadores e
invalida compatibilidade de rede. BLAKE3 não é uma afirmação de conformidade
FIPS; ML-DSA é a única primitiva desta etapa escolhida por FIPS 204.

## Assinaturas

Toda assinatura pertence a um `SigningDomain`, transmitido como a string de
contexto do FIPS 204:

| Domínio | Contexto | Uso |
| --- | --- | --- |
| `Transaction` | `ITACOIN:transaction:v1` | Autorização de transações on-chain |
| `Message` | `ITACOIN:message:v1` | Mensagens off-chain, como prova de posse de endereço |

Uma assinatura feita em um domínio não verifica em outro, então uma mensagem
assinada fora da cadeia não pode ser reaproveitada como autorização de
transação (achado V-02). Novos domínios exigem uma string nova; uma string
existente nunca deve ser reutilizada.

A assinatura é *hedged*: a variante aleatorizada do ML-DSA mistura 32 bytes do
CSPRNG do sistema operacional à chave. Duas assinaturas da mesma mensagem são
diferentes e ambas válidas. Isso reduz a exposição a ataques de injeção de
falha contra a variante determinística (achado V-03).

`PublicKey::from_bytes` aceita qualquer sequência de 1952 bytes, porque todo
padrão de bits é uma codificação ML-DSA-65 válida. Uma chave parseada não prova
que alguém possui a chave privada correspondente.

## Endereços

Um endereço é a codificação Bech32m de `versão (1 byte) || wallet_id (32 bytes)`
com um prefixo por rede: `itc` (mainnet), `titc` (testnet) e `ritc` (regtest).
O checksum detecta erros de digitação, e a versão (hoje só `0`) permite um
formato futuro sem ambiguidade. Use `Address::parse_for_network` em toda
entrada de usuário para recusar endereços de outra rede. O `wallet_id` só pode
ser derivado de uma `PublicKey` já parseada (achado V-08).

## Armazenamento de carteira

Uma `PrivateKey` contém a seed de 32 bytes da ML-DSA-65. A seed é material
secreto suficiente para reconstruir a chave e é a representação de backup
escolhida pela implementação RustCrypto. A carteira serializada (`ITCW`, versão
2, 145 bytes) contém:

```text
magic "ITCW" (4) || versão = 2 (1)
|| Argon2 memória KiB (u32) || Argon2 passadas (u32) || Argon2 lanes (u32)
|| salt (16) || nonce XChaCha (24)
|| wallet_id (32) || geração (u64)
|| ciphertext + tag (48)
```

Inteiros são big-endian. **Todos os 97 bytes do cabeçalho são os dados
autenticados do AEAD**: alterar magic, parâmetros, salt, nonce, `wallet_id` ou
geração faz a decriptação falhar (achados V-04 e V-05). Depois de decriptar, a
chave recuperada precisa corresponder ao `wallet_id` gravado.

O `wallet_id` e a geração podem ser lidos sem senha. `decrypt_checked` recusa,
antes de rodar a KDF, um arquivo de outra carteira (`WrongWallet`) ou com
geração inferior à última conhecida pelo chamador (`RolledBack`).

### Proteção contra rollback na prática

**O mecanismo.** A geração é um contador `u64` gravado em claro no cabeçalho e
autenticado pelo AEAD. Quem não sabe a senha não consegue aumentá-la: alterar
esse campo faz a decriptação falhar. Mas um arquivo antigo e legítimo continua
autêntico. Por isso o rollback só é detectável comparando a geração do arquivo
com um valor guardado **fora** dele:

1. A aplicação guarda o par `(wallet_id, última geração)` num local separado
   do arquivo da carteira: a configuração da aplicação, o chaveiro do sistema
   operacional ou, idealmente, um contador monotônico de hardware (TPM ou
   enclave seguro).
2. Cada regravação usa `geração + 1`, por `Wallet::encrypt` e
   `EncryptedWallet::replace`. Depois que a gravação termina, a aplicação
   atualiza o valor externo.
3. Ao abrir, a aplicação chama `decrypt_checked(senha, wallet_id, última
   geração)`.

Se a ordem do passo 2 for invertida (atualizar o contador antes de gravar),
uma queda no meio deixa a carteira com geração menor que o contador. Ela seria
recusada como rollback, embora não seja.

**O que `replace` garante sozinho.** `replace` recusa gravar sobre um arquivo
de outra carteira ou com geração maior ou igual. Isso evita que a própria
aplicação regrida o arquivo por engano. Não impede que alguém com acesso de
escrita copie um arquivo antigo por cima: só o valor externo detecta isso.

**O que ela não cobre.** Se o valor externo for perdido ou ficar no mesmo
disco que o atacante controla, a proteção se reduz a detectar a troca por
outra carteira (`WrongWallet`). Um atacante com acesso de escrita aos dois
locais pode fazer rollback sem ser detectado.

**Restaurar um backup antigo de propósito.** Nesta etapa, uma carteira contém
uma única chave, que nunca muda. Restaurar qualquer backup da mesma carteira
devolve exatamente a mesma chave e o mesmo endereço, e todos os fundos
continuam acessíveis. Não existe uma "chave gerada depois do backup" que
possa ser perdida. Por isso o rollback hoje é um risco de integridade, não de
perda de fundos. Para restaurar conscientemente, a aplicação deve:

1. mostrar o endereço gravado no backup (legível sem senha) e pedir
   confirmação;
2. avisar que a geração do backup é menor que a última conhecida;
3. decriptar com `decrypt` (sem mínimo) somente após a confirmação explícita;
4. regravar com `geração = última conhecida + 1`, para que o backup restaurado
   passe a ser a versão atual.

**Quando isso deixa de ser seguro.** Assim que o arquivo passar a guardar
estado que muda (várias chaves derivadas, rotação de chave após suspeita de
comprometimento, rótulos ou metadados), restaurar um backup antigo pode
perder chaves criadas depois dele, ou trazer de volta uma chave revogada. Uma
carteira com várias chaves deve então adotar uma das duas abordagens:
derivação determinística a partir de uma seed raiz (o backup antigo
regenera as chaves novas, com um *gap limit*) ou bloqueio do rollback
sem um fluxo de recuperação dedicado. Essa decisão é pré-requisito do
achado P-09 (rotação de chaves).

Para cada criptografia, o sistema operacional fornece um salt e nonce novos. A
senha passa por Argon2id v1.3; o padrão para carteiras novas é 64 MiB, três
passadas e quatro lanes (segunda opção recomendada pela RFC 9106). Os
parâmetros ficam no arquivo e precisam estar entre 19 MiB/2/1 e 1 GiB/16/16;
fora desses limites o arquivo é rejeitado, o que impede que um arquivo hostil
force uma alocação ilimitada. Senha incorreta e alteração de dados retornam o
mesmo erro de decriptação, reduzindo oráculos de autenticidade.

### Senha

`Password` toma posse do buffer da senha e o apaga ao ser descartado. A
política exige entre 12 e 1024 bytes (achado V-06). Comprimento é apenas um
piso: uma senha longa e previsível continua fraca contra ataque offline a um
arquivo roubado. Use um gerenciador de senhas para gerá-la.

### Arquivo em disco

- `write_new` cria o arquivo por um temporário com permissão `0600`,
  `fsync`, e um *hard link* atômico que nunca sobrescreve um arquivo existente.
- `replace` exige que o arquivo atual seja da mesma carteira e tenha geração
  estritamente menor, grava por temporário e `rename` atômico.
- Ambas sincronizam o diretório para que a operação sobreviva a uma queda.
- `read` recusa, em Unix, arquivos acessíveis por grupo ou outros usuários, e
  lê no máximo o tamanho fixo do formato.

Ainda não há *locking* entre processos: dois processos regravando a mesma
carteira ao mesmo tempo podem perder uma atualização (mas nunca gravam um
arquivo parcial).

Arquivos `ITCW` versão 1 são rejeitados. Aquele formato não autenticava o
cabeçalho e nunca guardou fundos.

Não há frase mnemônica nem formato de seed de recuperação nesta etapa. O backup
é o arquivo `ITCW` criptografado mais a senha, guardados separadamente. Perder
qualquer um dos dois torna a chave irrecuperável. Uma frase de recuperação só
deve ser adicionada após definir e testar um formato interoperável para
ML-DSA-65.

## Limites e riscos restantes

- `zeroize` reduz a vida de alguns segredos, mas não pode eliminar todas as
  cópias feitas pelo compilador, SO, paginação, crash dump ou depurador. Não
  há `mlock` nem desabilitação de core dump (achado V-07, parcialmente
  tratado).
- A força da carteira depende da senha e da disponibilidade correta do CSPRNG
  do sistema operacional.
- Ainda não há revisão de segurança externa, threat model, fuzzing, hardware
  wallet, rotação/revogação de chaves, vetores ACVP de assinatura, testes de
  interoperabilidade multi-implementação ou suporte de recovery phrase.
- A política de emissão, regras de consenso e codificação canônica de
  transações não existem ainda; portanto, esta etapa não deve guardar fundos
  reais ou ser apresentada como blockchain pronta para produção.
