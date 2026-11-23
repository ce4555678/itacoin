//! ITACOIN transactions, as specified in `docs/CODEC_PROPOSAL.md`.
//!
//! Every value of these types satisfies the stateless rules: list sizes,
//! canonical witness indices, non-zero outputs whose sum fits the supply, no
//! repeated outpoint, and the transaction size limit. Constructors and the
//! decoder enforce them, so a `Transaction` can never hold an invalid shape.
//! Rules that need the UTXO set are checked by
//! [`NormalTransaction::validate_spend`], given the outputs being spent.

use core::fmt;
use std::collections::HashSet;

use itacoin_codec::{CodecError, Decode, Encode, Reader, Writer, decode_exact};
use itacoin_crypto::{
    CryptoError, ML_DSA_65_PUBLIC_KEY_BYTES, ML_DSA_65_SIGNATURE_BYTES, PublicKey, Signature,
    SigningDomain, sighash, spent_outputs_hash, transaction_hash, verify, witness_hash,
};
use itacoin_primitives::{Amount, AmountError, Hash256, TransactionId, WalletId};

/// The only transaction version this release accepts.
pub const TRANSACTION_VERSION: u16 = 1;
/// Maximum encoded size of one transaction, witnesses included.
pub const MAX_TX_BYTES: usize = 100_000;
/// Maximum number of inputs of one transaction.
pub const MAX_TX_INPUTS: usize = 1_000;
/// Maximum number of outputs of one transaction.
pub const MAX_TX_OUTPUTS: usize = 1_000;

/// Encoded size of an [`Input`].
pub const INPUT_BYTES: usize = 32 + 2 + 2;
/// Encoded size of an [`Output`].
pub const OUTPUT_BYTES: usize = 1 + 8 + 32;
/// Encoded size of a [`Witness`].
pub const WITNESS_BYTES: usize = ML_DSA_65_PUBLIC_KEY_BYTES + ML_DSA_65_SIGNATURE_BYTES;
/// Encoded size of the smallest possible transaction (a one-output coinbase).
pub const MIN_TX_BYTES: usize = PREFIX_BYTES + 8 + 2 + OUTPUT_BYTES;

const PREFIX_BYTES: usize = 2 + 1;
const KIND_NORMAL: u8 = 0;
const KIND_COINBASE: u8 = 1;
const OUTPUT_KIND_WALLET: u8 = 0;

/// A reference to an output of an earlier transaction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OutPoint {
    /// The transaction that created the output.
    pub txid: TransactionId,
    /// The output's position in that transaction.
    pub index: u16,
}

/// A spend of an earlier output, authorized by one of the transaction's
/// witnesses.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Input {
    /// The output being spent.
    pub previous_output: OutPoint,
    /// Index of the witness whose key owns the spent output.
    pub witness_index: u16,
}

/// A payment of `amount` to the owner of `wallet_id`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output {
    /// The value paid; at least one satoshi inside a transaction.
    pub amount: Amount,
    /// The identifier of the public key that may spend the output.
    pub wallet_id: WalletId,
}

/// A public key and its signature over the transaction's sighash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Witness {
    /// The key whose wallet id owns the inputs pointing at this witness.
    pub public_key: PublicKey,
    /// ML-DSA-65 signature in [`SigningDomain::Transaction`].
    pub signature: Signature,
}

/// The witness-free part of a normal transaction: what the txid covers and
/// what the witnesses sign.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedTransaction {
    inputs: Vec<Input>,
    outputs: Vec<Output>,
    output_total: Amount,
    witness_count: usize,
}

impl UnsignedTransaction {
    /// Validates the stateless rules for inputs and outputs.
    ///
    /// Witness indices must appear in canonical order: walking the inputs,
    /// each new index is exactly one more than the largest seen so far.
    pub fn new(inputs: Vec<Input>, outputs: Vec<Output>) -> Result<Self, TransactionError> {
        if !(1..=MAX_TX_INPUTS).contains(&inputs.len()) {
            return Err(TransactionError::InputCount(inputs.len()));
        }
        let mut witness_count = 0_usize;
        let mut seen = HashSet::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let witness = usize::from(input.witness_index);
            if witness == witness_count {
                witness_count += 1;
            } else if witness > witness_count {
                return Err(TransactionError::WitnessOrder { input: index });
            }
            if !seen.insert(input.previous_output) {
                return Err(TransactionError::DuplicateOutPoint(input.previous_output));
            }
        }
        let output_total = check_outputs(&outputs)?;
        Ok(Self {
            inputs,
            outputs,
            output_total,
            witness_count,
        })
    }

    /// Returns the inputs in order.
    #[must_use]
    pub fn inputs(&self) -> &[Input] {
        &self.inputs
    }

    /// Returns the outputs in order.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Returns the sum of the outputs.
    #[must_use]
    pub const fn output_total(&self) -> Amount {
        self.output_total
    }

    /// Returns how many witnesses must sign this transaction.
    #[must_use]
    pub const fn witness_count(&self) -> usize {
        self.witness_count
    }

    /// Returns the transaction id, which excludes witnesses.
    #[must_use]
    pub fn txid(&self) -> TransactionId {
        let mut writer = Writer::with_capacity(self.body_len());
        self.encode_body(&mut writer);
        transaction_hash(&writer.into_bytes())
    }

    /// Returns the message every witness signs.
    ///
    /// `chain_id` is the genesis block id of the network. `spent` holds the
    /// outputs being spent, in input order.
    pub fn sighash(
        &self,
        chain_id: &Hash256,
        spent: &[Output],
    ) -> Result<Hash256, TransactionError> {
        if spent.len() != self.inputs.len() {
            return Err(TransactionError::SpentOutputCount {
                expected: self.inputs.len(),
                actual: spent.len(),
            });
        }
        let mut writer = Writer::with_capacity(spent.len() * OUTPUT_BYTES);
        for output in spent {
            output.encode(&mut writer);
        }
        Ok(sighash(
            chain_id,
            &self.txid(),
            &spent_outputs_hash(&writer.into_bytes()),
        ))
    }

    /// Attaches the witnesses, one per distinct witness index.
    ///
    /// Signatures are not verified here; see
    /// [`NormalTransaction::validate_spend`].
    pub fn with_witnesses(
        self,
        witnesses: Vec<Witness>,
    ) -> Result<NormalTransaction, TransactionError> {
        if witnesses.len() != self.witness_count {
            return Err(TransactionError::WitnessCount {
                expected: self.witness_count,
                actual: witnesses.len(),
            });
        }
        let transaction = NormalTransaction {
            unsigned: self,
            witnesses,
        };
        check_size(transaction.encoded_len())?;
        Ok(transaction)
    }

    fn body_len(&self) -> usize {
        PREFIX_BYTES + 2 + self.inputs.len() * INPUT_BYTES + 2 + self.outputs.len() * OUTPUT_BYTES
    }

    fn encode_body(&self, writer: &mut Writer) {
        writer.u16(TRANSACTION_VERSION);
        writer.u8(KIND_NORMAL);
        writer.count_u16(self.inputs.len());
        for input in &self.inputs {
            input.encode(writer);
        }
        encode_outputs(&self.outputs, writer);
    }
}

/// A transaction that spends existing outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalTransaction {
    unsigned: UnsignedTransaction,
    witnesses: Vec<Witness>,
}

impl NormalTransaction {
    /// Returns the witness-free part.
    #[must_use]
    pub const fn unsigned(&self) -> &UnsignedTransaction {
        &self.unsigned
    }

    /// Returns the witnesses in index order.
    #[must_use]
    pub fn witnesses(&self) -> &[Witness] {
        &self.witnesses
    }

    /// Checks every rule that needs the spent outputs and returns the fee.
    ///
    /// The caller looks `spent` up in the UTXO set, in input order. Checks run
    /// from cheapest to most expensive: key ownership by wallet id, distinct
    /// witness keys, value conservation, and only then ML-DSA verification.
    pub fn validate_spend(
        &self,
        chain_id: &Hash256,
        spent: &[Output],
    ) -> Result<Amount, TransactionError> {
        let inputs = self.unsigned.inputs();
        if spent.len() != inputs.len() {
            return Err(TransactionError::SpentOutputCount {
                expected: inputs.len(),
                actual: spent.len(),
            });
        }

        let wallet_ids: Vec<WalletId> = self
            .witnesses
            .iter()
            .map(|witness| witness.public_key.wallet_id())
            .collect();
        for (index, (input, output)) in inputs.iter().zip(spent).enumerate() {
            if wallet_ids[usize::from(input.witness_index)] != output.wallet_id {
                return Err(TransactionError::WrongKey { input: index });
            }
        }
        let mut distinct = HashSet::with_capacity(wallet_ids.len());
        for (index, wallet_id) in wallet_ids.iter().enumerate() {
            if !distinct.insert(wallet_id) {
                return Err(TransactionError::DuplicateWitness { witness: index });
            }
        }

        let mut input_total = Amount::ZERO;
        for output in spent {
            input_total = input_total
                .checked_add(output.amount)
                .map_err(TransactionError::Amount)?;
        }
        let fee = input_total
            .checked_sub(self.unsigned.output_total())
            .map_err(|_| TransactionError::InsufficientInputs)?;

        let message = self.unsigned.sighash(chain_id, spent)?;
        for (index, witness) in self.witnesses.iter().enumerate() {
            verify(
                &witness.public_key,
                SigningDomain::Transaction,
                message.as_bytes(),
                &witness.signature,
            )
            .map_err(|error| TransactionError::InvalidSignature {
                witness: index,
                error,
            })?;
        }
        Ok(fee)
    }

    fn witness_bytes(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(self.witnesses.len() * WITNESS_BYTES);
        for witness in &self.witnesses {
            witness.encode(&mut writer);
        }
        writer.into_bytes()
    }
}

/// The first transaction of a block, which creates new coins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinbaseTransaction {
    height: u64,
    outputs: Vec<Output>,
    output_total: Amount,
}

impl CoinbaseTransaction {
    /// Validates a coinbase for the block at `height`.
    ///
    /// Whether the total equals subsidy plus fees is a consensus rule checked
    /// by the chain, not here.
    pub fn new(height: u64, outputs: Vec<Output>) -> Result<Self, TransactionError> {
        let output_total = check_outputs(&outputs)?;
        let coinbase = Self {
            height,
            outputs,
            output_total,
        };
        check_size(coinbase.encoded_len())?;
        Ok(coinbase)
    }

    /// Returns the block height this coinbase belongs to.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the outputs in order.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        &self.outputs
    }

    /// Returns the sum of the outputs.
    #[must_use]
    pub const fn output_total(&self) -> Amount {
        self.output_total
    }
}

/// A transaction of either kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transaction {
    /// Spends existing outputs.
    Normal(NormalTransaction),
    /// Creates new coins; only the first transaction of a block.
    Coinbase(CoinbaseTransaction),
}

impl Transaction {
    /// Decodes one transaction that occupies all of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        decode_exact(bytes, MAX_TX_BYTES)
    }

    /// Returns the transaction id, which excludes witnesses.
    #[must_use]
    pub fn txid(&self) -> TransactionId {
        match self {
            Self::Normal(transaction) => transaction.unsigned.txid(),
            Self::Coinbase(coinbase) => transaction_hash(&coinbase.to_bytes()),
        }
    }

    /// Returns the hash of the witness section; a coinbase has none.
    #[must_use]
    pub fn witness_hash(&self) -> Hash256 {
        match self {
            Self::Normal(transaction) => witness_hash(&transaction.witness_bytes()),
            Self::Coinbase(_) => witness_hash(&[]),
        }
    }

    /// Returns the inputs; empty for a coinbase.
    #[must_use]
    pub fn inputs(&self) -> &[Input] {
        match self {
            Self::Normal(transaction) => transaction.unsigned.inputs(),
            Self::Coinbase(_) => &[],
        }
    }

    /// Returns the outputs.
    #[must_use]
    pub fn outputs(&self) -> &[Output] {
        match self {
            Self::Normal(transaction) => transaction.unsigned.outputs(),
            Self::Coinbase(coinbase) => coinbase.outputs(),
        }
    }

    /// Returns how many signatures validating this transaction verifies.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        match self {
            Self::Normal(transaction) => transaction.witnesses.len(),
            Self::Coinbase(_) => 0,
        }
    }

    /// Returns whether this is a coinbase.
    #[must_use]
    pub const fn is_coinbase(&self) -> bool {
        matches!(self, Self::Coinbase(_))
    }
}

fn check_outputs(outputs: &[Output]) -> Result<Amount, TransactionError> {
    if !(1..=MAX_TX_OUTPUTS).contains(&outputs.len()) {
        return Err(TransactionError::OutputCount(outputs.len()));
    }
    let mut total = Amount::ZERO;
    for (index, output) in outputs.iter().enumerate() {
        if output.amount == Amount::ZERO {
            return Err(TransactionError::ZeroOutput { output: index });
        }
        total = total
            .checked_add(output.amount)
            .map_err(TransactionError::Amount)?;
    }
    Ok(total)
}

fn check_size(size: usize) -> Result<(), TransactionError> {
    if size <= MAX_TX_BYTES {
        Ok(())
    } else {
        Err(TransactionError::Codec(CodecError::TooLarge {
            maximum: MAX_TX_BYTES,
            actual: size,
        }))
    }
}

fn encode_outputs(outputs: &[Output], writer: &mut Writer) {
    writer.count_u16(outputs.len());
    for output in outputs {
        output.encode(writer);
    }
}

fn decode_outputs(reader: &mut Reader<'_>) -> Result<Vec<Output>, TransactionError> {
    let count = reader.count_u16(1..=MAX_TX_OUTPUTS, OUTPUT_BYTES)?;
    (0..count).map(|_| Output::decode(reader)).collect()
}

impl Encode for Input {
    fn encode(&self, writer: &mut Writer) {
        self.previous_output.txid.encode(writer);
        writer.u16(self.previous_output.index);
        writer.u16(self.witness_index);
    }

    fn encoded_len(&self) -> usize {
        INPUT_BYTES
    }
}

impl Decode for Input {
    type Error = CodecError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            previous_output: OutPoint {
                txid: TransactionId::decode(reader)?,
                index: reader.u16()?,
            },
            witness_index: reader.u16()?,
        })
    }
}

impl Encode for Output {
    fn encode(&self, writer: &mut Writer) {
        writer.u8(OUTPUT_KIND_WALLET);
        self.amount.encode(writer);
        self.wallet_id.encode(writer);
    }

    fn encoded_len(&self) -> usize {
        OUTPUT_BYTES
    }
}

impl Decode for Output {
    type Error = TransactionError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, TransactionError> {
        let kind = reader.u8()?;
        if kind != OUTPUT_KIND_WALLET {
            return Err(TransactionError::UnknownOutputKind(kind));
        }
        Ok(Self {
            amount: Amount::decode(reader)?,
            wallet_id: WalletId::decode(reader)?,
        })
    }
}

impl Encode for Witness {
    fn encode(&self, writer: &mut Writer) {
        self.public_key.encode(writer);
        self.signature.encode(writer);
    }

    fn encoded_len(&self) -> usize {
        WITNESS_BYTES
    }
}

impl Decode for Witness {
    type Error = CodecError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            public_key: PublicKey::decode(reader)?,
            signature: Signature::decode(reader)?,
        })
    }
}

impl Encode for NormalTransaction {
    fn encode(&self, writer: &mut Writer) {
        self.unsigned.encode_body(writer);
        for witness in &self.witnesses {
            witness.encode(writer);
        }
    }

    fn encoded_len(&self) -> usize {
        self.unsigned.body_len() + self.witnesses.len() * WITNESS_BYTES
    }
}

impl Encode for CoinbaseTransaction {
    fn encode(&self, writer: &mut Writer) {
        writer.u16(TRANSACTION_VERSION);
        writer.u8(KIND_COINBASE);
        writer.u64(self.height);
        encode_outputs(&self.outputs, writer);
    }

    fn encoded_len(&self) -> usize {
        PREFIX_BYTES + 8 + 2 + self.outputs.len() * OUTPUT_BYTES
    }
}

impl Encode for Transaction {
    fn encode(&self, writer: &mut Writer) {
        match self {
            Self::Normal(transaction) => transaction.encode(writer),
            Self::Coinbase(coinbase) => coinbase.encode(writer),
        }
    }

    fn encoded_len(&self) -> usize {
        match self {
            Self::Normal(transaction) => transaction.encoded_len(),
            Self::Coinbase(coinbase) => coinbase.encoded_len(),
        }
    }
}

impl Decode for Transaction {
    type Error = TransactionError;

    fn decode(reader: &mut Reader<'_>) -> Result<Self, TransactionError> {
        let version = reader.u16()?;
        if version != TRANSACTION_VERSION {
            return Err(TransactionError::UnsupportedVersion(version));
        }
        match reader.u8()? {
            KIND_NORMAL => {
                let count = reader.count_u16(1..=MAX_TX_INPUTS, INPUT_BYTES)?;
                let inputs = (0..count)
                    .map(|_| Input::decode(reader))
                    .collect::<Result<Vec<_>, _>>()?;
                let outputs = decode_outputs(reader)?;
                let unsigned = UnsignedTransaction::new(inputs, outputs)?;
                let count = unsigned.witness_count();
                reader.ensure(count * WITNESS_BYTES)?;
                let witnesses = (0..count)
                    .map(|_| Witness::decode(reader))
                    .collect::<Result<Vec<_>, _>>()?;
                unsigned.with_witnesses(witnesses).map(Self::Normal)
            }
            KIND_COINBASE => {
                let height = reader.u64()?;
                let outputs = decode_outputs(reader)?;
                CoinbaseTransaction::new(height, outputs).map(Self::Coinbase)
            }
            kind => Err(TransactionError::UnknownKind(kind)),
        }
    }
}

/// Errors from building, decoding or validating a transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransactionError {
    /// The bytes are not a canonical encoding.
    Codec(CodecError),
    /// The version is not [`TRANSACTION_VERSION`].
    UnsupportedVersion(u16),
    /// The transaction kind byte is unknown.
    UnknownKind(u8),
    /// The output kind byte is unknown.
    UnknownOutputKind(u8),
    /// The number of inputs is outside `1..=MAX_TX_INPUTS`.
    InputCount(usize),
    /// The number of outputs is outside `1..=MAX_TX_OUTPUTS`.
    OutputCount(usize),
    /// An input introduces a witness index out of canonical order.
    WitnessOrder {
        /// Position of the offending input.
        input: usize,
    },
    /// Two inputs spend the same output.
    DuplicateOutPoint(OutPoint),
    /// An output pays zero.
    ZeroOutput {
        /// Position of the offending output.
        output: usize,
    },
    /// A monetary sum overflowed or exceeded the maximum supply.
    Amount(AmountError),
    /// The number of witnesses differs from the distinct witness indices.
    WitnessCount {
        /// Required number of witnesses.
        expected: usize,
        /// Provided number of witnesses.
        actual: usize,
    },
    /// The number of spent outputs differs from the number of inputs.
    SpentOutputCount {
        /// Number of inputs.
        expected: usize,
        /// Number of spent outputs provided.
        actual: usize,
    },
    /// An input's witness key does not own the output it spends.
    WrongKey {
        /// Position of the offending input.
        input: usize,
    },
    /// Two witnesses carry keys with the same wallet id.
    DuplicateWitness {
        /// Position of the repeated witness.
        witness: usize,
    },
    /// The outputs are worth more than the spent outputs.
    InsufficientInputs,
    /// A witness signature does not verify.
    InvalidSignature {
        /// Position of the offending witness.
        witness: usize,
        /// The verification error.
        error: CryptoError,
    },
}

impl From<CodecError> for TransactionError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl fmt::Display for TransactionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(error) => write!(formatter, "invalid transaction encoding: {error}"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported transaction version {version}")
            }
            Self::UnknownKind(kind) => write!(formatter, "unknown transaction kind {kind}"),
            Self::UnknownOutputKind(kind) => write!(formatter, "unknown output kind {kind}"),
            Self::InputCount(count) => write!(formatter, "invalid input count {count}"),
            Self::OutputCount(count) => write!(formatter, "invalid output count {count}"),
            Self::WitnessOrder { input } => {
                write!(formatter, "input {input} has a non-canonical witness index")
            }
            Self::DuplicateOutPoint(outpoint) => write!(
                formatter,
                "output {}:{} is spent twice",
                outpoint.txid, outpoint.index
            ),
            Self::ZeroOutput { output } => write!(formatter, "output {output} pays zero"),
            Self::Amount(error) => write!(formatter, "invalid transaction value: {error}"),
            Self::WitnessCount { expected, actual } => {
                write!(formatter, "expected {expected} witnesses, got {actual}")
            }
            Self::SpentOutputCount { expected, actual } => {
                write!(formatter, "expected {expected} spent outputs, got {actual}")
            }
            Self::WrongKey { input } => {
                write!(formatter, "input {input} is not owned by its witness key")
            }
            Self::DuplicateWitness { witness } => {
                write!(formatter, "witness {witness} repeats another witness key")
            }
            Self::InsufficientInputs => formatter.write_str("outputs exceed inputs"),
            Self::InvalidSignature { witness, error } => {
                write!(formatter, "witness {witness} signature is invalid: {error}")
            }
        }
    }
}

impl std::error::Error for TransactionError {}

#[cfg(test)]
mod tests;
