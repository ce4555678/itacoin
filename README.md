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
mempool com RBF e *compact blocks*.
Ele não implementa mineração, RPC nem um binário de nó. Não está pronto para produção ou para guardar fundos reais.

## Segurança e compatibilidade

`itacoin-crypto` usa `ml-dsa` 0.1.2, a implementação RustCrypto de ML-DSA
descrita no FIPS 204. A própria dependência declara que ainda não recebeu uma
auditoria independente. A API usa somente ML-DSA-65 puro e hedged, com um
contexto FIPS 204 por domínio de assinatura (transação ou mensagem), e a
codificação bruta especificada por FIPS 204 (chave pública: 1952 bytes;
assinatura: 3309 bytes). Uma revisão criptográfica independente, testes de
interoperabilidade adicionais e uma política formal de rotação de chaves são
pré-requisitos para produção.

A chave privada da carteira é armazenada como a seed ML-DSA de 32 bytes,
criptografada localmente com Argon2id e XChaCha20-Poly1305. Não existe frase de
recuperação nesta etapa: faça backup do arquivo criptografado e mantenha a senha
em um gerenciador seguro. Perder ambos torna a chave irrecuperável. Uma seed
frase não será criada sem definir um formato de backup interoperável para
ML-DSA-65.

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

## Escopo futuro reservado

Os diretórios para os demais componentes são reservados para etapas futuras:
`itacoin-miner`,
`itacoin-rpc` e `itacoin-node`.
