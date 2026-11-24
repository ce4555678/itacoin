# ITACOIN

Fundação técnica inicial da ITACOIN, uma blockchain Layer 1 experimental em Rust.

O workspace implementa primitivas monetárias, endereços Bech32m com checksum,
hashes BLAKE3 com separação de domínio, Merkle tree no formato RFC 6962,
assinaturas ML-DSA-65 hedged e vinculadas a um domínio, uma carteira local
criptografada com arquivo autenticado e proteção contra rollback, e o
[codec canônico](docs/CODEC_PROPOSAL.md) de transações e blocos, um UTXO set
persistido com [redb](https://docs.rs/redb) e resistente a quedas, e as regras
de [consenso](docs/CONSENSUS_PROPOSAL.md): emissão, prova de trabalho Argon2id,
dificuldade aserti3-2d, timestamps e escolha da cadeia de maior trabalho com
reorganização. A [rede P2P](docs/NETWORK_PROPOSAL.md) usa transporte
criptografado pós-quântico (X25519 + ML-KEM-768), sincronização por cabeçalhos,
mempool com RBF e *compact blocks*. O [nó](docs/NODE_PROPOSAL.md)
`itacoin-node` junta rede, JSON-RPC e um minerador embutido de várias
threads; `itacoin-cli` é o cliente do RPC. A [carteira](docs/WALLET_PROPOSAL.md)
`itacoin-wallet` deriva todas as chaves de um segredo mestre com backup
`itcseed1…` e monta, assina e envia transações pelo nó. O
[estado da cadeia](docs/STORAGE_PROPOSAL.md) fica em disco com um cache de
moedas limitado, e `--prune-witnesses` descarta as testemunhas de blocos
antigos (≈ 7,6 GB por ano em vez de ≈ 263 GB com blocos cheios). Não está pronto
para produção ou para guardar fundos reais.

## Segurança e compatibilidade

`itacoin-crypto` usa `ml-dsa` 0.1.2, a implementação RustCrypto de ML-DSA
descrita no FIPS 204. A própria dependência declara que ainda não recebeu uma
auditoria independente. A API usa somente ML-DSA-65 puro e hedged, com um
contexto FIPS 204 por domínio de assinatura (transação ou mensagem), e a
codificação bruta especificada por FIPS 204 (chave pública: 1952 bytes;
assinatura: 3309 bytes). Uma revisão criptográfica independente, testes de
interoperabilidade adicionais e uma política formal de rotação de chaves são
pré-requisitos para produção.

A carteira guarda um segredo mestre de 32 bytes, criptografado localmente
com Argon2id e XChaCha20-Poly1305, do qual todas as chaves ML-DSA-65 são
derivadas. O backup é o texto `itcseed1…` (Bech32m, com versão e checksum)
mostrado na criação; ele não é uma frase BIP 39 e não deve ser digitado em
carteiras de outras moedas. Quem tem o backup gasta os fundos.

Os achados da [auditoria de segurança](docs/SECURITY_AUDIT.md) e o estado de
cada correção estão em [docs/REMEDIATION.md](docs/REMEDIATION.md). As
restrições que as próximas etapas devem respeitar (tamanho das assinaturas
pós-quânticas, txid, limites de bloco e aritmética monetária) estão em
[docs/PROTOCOL_REQUIREMENTS.md](docs/PROTOCOL_REQUIREMENTS.md).

## Desenvolvimento

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

## Emissão

`MAX_SUPPLY` representa exatamente 100.000.000 ITC (10.000.000.000.000.000
unidades mínimas). A [curva de emissão](docs/EMISSION_PROPOSAL.md) é linear decrescente em 100
eras de 262.800 blocos (≈ 100 anos), e um teste soma todas as recompensas e
exige igualdade exata com esse valor.

## Rodando um nó

```sh
cargo build --release
# Regtest local: blocos na hora, sem PoW real.
target/release/itacoin-node --network regtest
target/release/itacoin-cli --network regtest generatetoaddress 10 <endereço ritc1…>
target/release/itacoin-cli --network regtest getblockchaininfo

# Testnet, minerando com núcleos − 1.
target/release/itacoin-node --network testnet --mine --mine-address <endereço titc1…>
```

```sh
# Carteira (o nó precisa estar rodando).
target/release/itacoin-wallet --network regtest create
target/release/itacoin-wallet --network regtest receive
target/release/itacoin-wallet --network regtest send <endereço> 1.5
```

`--network` é obrigatório. Os dados ficam em `~/.itacoin/<rede>/` (mude a
base com `--datadir`), onde também pode ficar um `itacoin.toml` com as mesmas
opções da linha de comando. O RPC escuta só em loopback e autentica pelo
arquivo `.cookie` do diretório de dados, que o `itacoin-cli` lê sozinho. A
mainnet só existe num build com `--features mainnet`, até as revisões
criptográficas pendentes. O nó nunca carrega chave privada: transações
chegam assinadas por `sendrawtransaction`.
