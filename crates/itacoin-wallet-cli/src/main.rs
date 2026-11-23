//! `itacoin-wallet`: the command-line wallet (`docs/WALLET_PROPOSAL.md`).
//!
//! There is no resident process: each command opens the files, decrypts the
//! master secret only when it must sign or derive, and exits.

use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use clap::{Parser, Subcommand};
use itacoin_codec::Encode;
use itacoin_consensus::ConsensusParams;
use itacoin_crypto::KeyPair;
use itacoin_primitives::{Address, Amount, Hash256, Network, WalletId};
use itacoin_rpc::{
    network_name, parse_network,
    text::{encode_base64url, parse_sat},
};
use itacoin_transaction::{MAX_TX_BYTES, Output, Transaction};
use itacoin_wallet::{
    Branch, EncryptedWallet, MasterSecret, Password, WalletError, WalletKind, backup,
    builder::{self, ChangeTo, Coin, MAX_KEYS_PER_TX, Payment, Plan},
};
use zeroize::Zeroizing;

mod node;
mod state;

use node::{Node, coin_key, itc, itc_amount};
use state::{Kind, POOL, PaymentRecord, SentRecord, State, Status, parse_wallet_id, slot};

/// Fee above this share of the amount sent asks for a second confirmation.
const HIGH_FEE_PERCENT: u128 = 1;
/// Fee rate above this asks for a second confirmation.
const HIGH_FEE_RATE: u64 = 1_000;
const DEFAULT_GAP: u32 = 100;

/// The ITACOIN command-line wallet.
#[derive(Debug, Parser)]
#[command(name = "itacoin-wallet", version, about)]
struct Cli {
    /// Network: mainnet, testnet or regtest.
    #[arg(long)]
    network: String,
    /// Base data directory (default ~/.itacoin).
    #[arg(long)]
    datadir: Option<PathBuf>,
    /// Wallet name.
    #[arg(long, default_value = "default")]
    wallet: String,
    /// Node RPC address (default 127.0.0.1 and the network's RPC port).
    #[arg(long)]
    rpc_connect: Option<String>,
    /// RPC user; the password comes from ITACOIN_RPC_PASSWORD. Without it,
    /// the node's cookie is used.
    #[arg(long)]
    rpc_user: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a wallet and show its backup.
    Create,
    /// Restore a wallet from an itcseed1… backup read from the input.
    Restore {
        /// Stop after this many unused addresses in a row.
        #[arg(long, default_value_t = DEFAULT_GAP)]
        gap: u32,
    },
    /// Show the backup again.
    Backup,
    /// Hand out the next receiving address.
    Receive {
        /// A label for the address.
        #[arg(long)]
        label: Option<String>,
    },
    /// List addresses handed out and their balances.
    Addresses,
    /// Show the balance.
    Balance,
    /// List coins grouped by key.
    Coins,
    /// Send ITC to an address.
    Send {
        /// Destination address.
        address: String,
        /// Amount in ITC (up to 8 decimals), or satoshis with --sat.
        amount: String,
        /// The amount is in satoshis.
        #[arg(long)]
        sat: bool,
        /// Fee rate in satoshis per byte (default: estimatefee).
        #[arg(long)]
        fee_rate: Option<u64>,
        /// Confirmation target in blocks for the fee estimate.
        #[arg(long, default_value_t = 6)]
        target: u64,
        /// Send change back to the largest input's key instead of a new
        /// address: cheaper, less private.
        #[arg(long)]
        change_to_input: bool,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
        /// Build and sign, print the transaction, do not send.
        #[arg(long)]
        dry_run: bool,
        /// Accept a fee above 1% of the amount or 1000 sat/byte.
        #[arg(long)]
        allow_high_fee: bool,
    },
    /// Join the coins of several keys into one new address.
    Consolidate {
        /// Most keys to join in one transaction.
        #[arg(long, default_value_t = MAX_KEYS_PER_TX)]
        max_keys: usize,
        /// Fee rate in satoshis per byte (default: estimatefee).
        #[arg(long)]
        fee_rate: Option<u64>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Replace an unconfirmed transaction with one paying a higher fee.
    Bumpfee {
        /// The transaction to replace.
        txid: String,
        /// New fee rate in satoshis per byte.
        #[arg(long)]
        fee_rate: Option<u64>,
        /// Do not ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// List sent transactions and their status.
    History,
    /// Search the chain for coins again.
    Rescan {
        /// Stop after this many unused addresses in a row.
        #[arg(long, default_value_t = DEFAULT_GAP)]
        gap: u32,
    },
    /// Change the password.
    Passwd,
    /// Show wallet details.
    Info,
    /// Adopt a single-key ITCW v2 wallet file.
    ImportV2 {
        /// The v2 file.
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    let warnings = itacoin_process::harden();
    let cli = Cli::parse();
    for warning in warnings {
        eprintln!("warning: {warning}");
    }
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("itacoin-wallet: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Everything a command needs to find.
struct Wallet {
    network: Network,
    params: ConsensusParams,
    base: PathBuf,
    dir: PathBuf,
    rpc_connect: Option<String>,
    rpc_user: Option<String>,
}

/// Decrypted keys, wiped on drop.
enum Secrets {
    Master(MasterSecret),
    Single(Box<KeyPair>),
}

impl Wallet {
    fn file(&self) -> PathBuf {
        self.dir.join("wallet.itcw")
    }

    fn state_path(&self) -> PathBuf {
        self.dir
            .join(format!("state-{}.json", network_name(self.network)))
    }

    fn node(&self) -> Result<Node, String> {
        Node::connect(
            &self.base,
            self.network,
            self.rpc_connect.as_deref(),
            self.rpc_user.as_deref(),
        )
    }

    fn read_file(&self) -> Result<EncryptedWallet, String> {
        EncryptedWallet::read(&self.file()).map_err(|error| match error {
            WalletError::Io(io) if io.kind() == std::io::ErrorKind::NotFound => {
                format!("no wallet at {}; run create or restore", self.dir.display())
            }
            other => format!("could not read {}: {other}", self.file().display()),
        })
    }

    /// The state, created (with the password) if this network has none yet.
    fn state(&self) -> Result<State, String> {
        if let Some(state) = State::load(&self.state_path())? {
            return Ok(state);
        }
        let file = self.read_file()?;
        let kind = match file.kind() {
            WalletKind::Master => Kind::Master,
            WalletKind::SingleKey => Kind::Single,
        };
        let mut state = State::new(
            network_name(self.network),
            kind,
            file.identity(),
            file.generation(),
        );
        eprintln!(
            "first use of this wallet on {}: deriving addresses",
            network_name(self.network)
        );
        let secrets = self.unlock(&file, &mut state)?;
        self.extend(&secrets, &mut state)?;
        state.save(&self.state_path())?;
        Ok(state)
    }

    /// Decrypts the wallet file after the identity and rollback checks.
    fn unlock(&self, file: &EncryptedWallet, state: &mut State) -> Result<Secrets, String> {
        if file.identity().to_string() != state.fingerprint {
            return Err("the wallet file does not match its state file".into());
        }
        if file.generation() < state.generation {
            return Err(format!(
                "the wallet file is older (generation {}) than one already seen ({}); \
                 an old copy was restored",
                file.generation(),
                state.generation
            ));
        }
        let password = password("Password: ")?;
        let secrets = match file.kind() {
            WalletKind::Master => Secrets::Master(
                file.decrypt_master(&password)
                    .map_err(|_| "wrong password or damaged wallet file")?,
            ),
            WalletKind::SingleKey => Secrets::Single(Box::new(
                file.decrypt(&password)
                    .map_err(|_| "wrong password or damaged wallet file")?
                    .into_key_pair(),
            )),
        };
        state.generation = file.generation();
        Ok(secrets)
    }

    /// Derives keys until each branch has [`POOL`] addresses in stock.
    fn extend(&self, secrets: &Secrets, state: &mut State) -> Result<(), String> {
        match secrets {
            Secrets::Single(pair) => {
                state.add_key(pair.public_key.wallet_id(), Branch::Receive, 0);
                state.derived = [1, 0];
            }
            Secrets::Master(master) => {
                for branch in [Branch::Receive, Branch::Change] {
                    let target = state.next[slot(branch)].saturating_add(POOL);
                    while state.derived[slot(branch)] < target {
                        let index = state.derived[slot(branch)];
                        let pair = master
                            .derive(self.network, branch, index)
                            .map_err(|error| error.to_string())?;
                        state.add_key(pair.public_key.wallet_id(), branch, index);
                        state.derived[slot(branch)] = index + 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn key_pair(
        &self,
        secrets: &Secrets,
        state: &State,
        wallet_id: &WalletId,
    ) -> Result<KeyPair, String> {
        match secrets {
            Secrets::Single(pair) if pair.public_key.wallet_id() == *wallet_id => copy_key(pair),
            Secrets::Single(_) => Err(format!("no key for {wallet_id}")),
            Secrets::Master(master) => {
                let record = state
                    .key(wallet_id)
                    .ok_or_else(|| format!("no key for {wallet_id}"))?;
                let branch = Branch::from_byte(record.branch).ok_or("damaged state file")?;
                master
                    .derive(self.network, branch, record.index)
                    .map_err(|error| error.to_string())
            }
        }
    }

    fn address(&self, wallet_id: WalletId) -> String {
        Address::new(self.network, wallet_id).to_string()
    }
}

/// Copies a key pair through its zeroized seed; private keys are not
/// `Clone` on purpose.
fn copy_key(pair: &KeyPair) -> Result<KeyPair, String> {
    let private_key = itacoin_crypto::PrivateKey::from_seed(pair.private_key.to_seed().as_ref())
        .map_err(|error| error.to_string())?;
    Ok(KeyPair {
        private_key,
        public_key: pair.public_key.clone(),
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn password(prompt: &str) -> Result<Password, String> {
    let text = itacoin_process::read_secret(prompt).map_err(|error| error.to_string())?;
    Password::new(text.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn new_password() -> Result<Password, String> {
    let first = itacoin_process::read_secret("New password (12 bytes or more): ")
        .map_err(|error| error.to_string())?;
    let second =
        itacoin_process::read_secret("Repeat the password: ").map_err(|error| error.to_string())?;
    if first.as_bytes() != second.as_bytes() {
        return Err("the passwords differ".into());
    }
    Password::new(first.as_bytes().to_vec()).map_err(|error| error.to_string())
}

fn confirm(question: &str) -> Result<bool, String> {
    let answer = itacoin_process::read_line(question).map_err(|error| error.to_string())?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "s" | "sim"
    ))
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn run(cli: Cli) -> Result<(), String> {
    let network =
        parse_network(&cli.network).ok_or_else(|| format!("unknown network {:?}", cli.network))?;
    let params = match network {
        Network::Mainnet => ConsensusParams::mainnet(),
        Network::Testnet => ConsensusParams::testnet(),
        Network::Regtest => ConsensusParams::regtest(),
    };
    if !valid_name(&cli.wallet) {
        return Err("wallet names use letters, digits, - and _ (at most 64)".into());
    }
    let base = cli
        .datadir
        .clone()
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".itacoin")))
        .ok_or("no home directory; use --datadir")?;
    let dir = base.join("wallets").join(&cli.wallet);
    let wallet = Wallet {
        network,
        params,
        base,
        dir,
        rpc_connect: cli.rpc_connect,
        rpc_user: cli.rpc_user,
    };
    match cli.command {
        Command::Create => create(&wallet),
        Command::Restore { gap } => restore(&wallet, gap),
        Command::Backup => show_backup(&wallet),
        Command::Receive { label } => receive(&wallet, label),
        Command::Addresses => addresses(&wallet),
        Command::Balance => balance(&wallet),
        Command::Coins => coins(&wallet),
        Command::Send {
            address,
            amount,
            sat,
            fee_rate,
            target,
            change_to_input,
            yes,
            dry_run,
            allow_high_fee,
        } => {
            let destination = Address::parse_for_network(&address, network)
                .map_err(|error| format!("{address}: {error}"))?;
            let amount = if sat {
                parse_sat(&amount).map_err(|_| "invalid amount in satoshis")?
            } else {
                Amount::from_itc_str(&amount).map_err(|error| format!("invalid amount: {error}"))?
            };
            if amount == Amount::ZERO {
                return Err("the amount must be positive".into());
            }
            send(
                &wallet,
                &SendOptions {
                    payments: vec![Output {
                        amount,
                        wallet_id: destination.wallet_id(),
                    }],
                    fee_rate,
                    target,
                    change_to_input,
                    yes,
                    dry_run,
                    allow_high_fee,
                },
            )
        }
        Command::Consolidate {
            max_keys,
            fee_rate,
            yes,
        } => consolidate(&wallet, max_keys, fee_rate, yes),
        Command::Bumpfee {
            txid,
            fee_rate,
            yes,
        } => bumpfee(&wallet, &txid, fee_rate, yes),
        Command::History => history(&wallet),
        Command::Rescan { gap } => rescan(&wallet, gap),
        Command::Passwd => passwd(&wallet),
        Command::Info => info(&wallet),
        Command::ImportV2 { file } => import_v2(&wallet, &file),
    }
}

// ------------------------------------------------------------- creation

fn prepare_dir(wallet: &Wallet) -> Result<(), String> {
    if wallet.file().exists() {
        return Err(format!(
            "a wallet already exists at {}",
            wallet.dir.display()
        ));
    }
    itacoin_process::create_data_dir(&wallet.dir)
        .map_err(|error| format!("could not create {}: {error}", wallet.dir.display()))
}

fn save_new(wallet: &Wallet, master: &MasterSecret, password: &Password) -> Result<State, String> {
    let file =
        EncryptedWallet::encrypt_master(master, password, 0).map_err(|error| error.to_string())?;
    file.write_new(&wallet.file())
        .map_err(|error| format!("could not write the wallet: {error}"))?;
    let mut state = State::new(
        network_name(wallet.network),
        Kind::Master,
        file.identity(),
        0,
    );
    let secrets = Secrets::Master(MasterSecret::from_bytes(*master.as_bytes()));
    wallet.extend(&secrets, &mut state)?;
    Ok(state)
}

fn create(wallet: &Wallet) -> Result<(), String> {
    prepare_dir(wallet)?;
    let password = new_password()?;
    let master = MasterSecret::generate();
    let text = backup::encode(&master);
    println!("Write down this backup. It recovers every address of this wallet:");
    println!();
    println!("{}", text.as_str());
    println!();
    println!("Anyone who has it can spend your funds. It is shown again only by `backup`.");
    let tail = &text[text.len() - 8..];
    let typed = Zeroizing::new(
        itacoin_process::read_line("Type the last 8 characters of the backup to confirm: ")
            .map_err(|error| error.to_string())?,
    );
    if typed.trim() != tail {
        return Err("the confirmation does not match; no wallet was created".into());
    }
    let state = save_new(wallet, &master, &password)?;
    state.save(&wallet.state_path())?;
    println!("Wallet created. Fingerprint {}", state.fingerprint);
    Ok(())
}

fn restore(wallet: &Wallet, gap: u32) -> Result<(), String> {
    prepare_dir(wallet)?;
    let text =
        itacoin_process::read_secret("Backup (itcseed1…): ").map_err(|error| error.to_string())?;
    let master = backup::decode(&text).map_err(|error| error.to_string())?;
    let password = new_password()?;
    let mut state = save_new(wallet, &master, &password)?;
    state.save(&wallet.state_path())?;
    let node = wallet.node()?;
    scan(wallet, &node, &Secrets::Master(master), &mut state, gap)?;
    state.save(&wallet.state_path())?;
    println!(
        "Wallet restored: {} receiving and {} change addresses in use.",
        state.next[0], state.next[1]
    );
    print_balance(wallet, &node, &state)
}

/// Finds the last used index of each branch, deriving in batches.
fn scan(
    wallet: &Wallet,
    node: &Node,
    secrets: &Secrets,
    state: &mut State,
    gap: u32,
) -> Result<(), String> {
    let Secrets::Master(master) = secrets else {
        return Ok(());
    };
    let gap = gap.max(1);
    for branch in [Branch::Receive, Branch::Change] {
        let mut last_used: Option<u32> = None;
        let mut start = 0_u32;
        loop {
            let end = start.saturating_add(POOL);
            let mut batch = Vec::new();
            for index in start..end {
                let pair = master
                    .derive(wallet.network, branch, index)
                    .map_err(|error| error.to_string())?;
                let wallet_id = pair.public_key.wallet_id();
                state.add_key(wallet_id, branch, index);
                batch.push((index, wallet_id));
            }
            state.derived[slot(branch)] = state.derived[slot(branch)].max(end);
            let ids: Vec<WalletId> = batch.iter().map(|(_, id)| *id).collect();
            let view = node.coins(&ids)?;
            let used: HashSet<WalletId> = view
                .confirmed
                .iter()
                .map(|coin| coin.coin.output.wallet_id)
                .chain(view.unconfirmed.iter().map(|coin| coin.output.wallet_id))
                .collect();
            for (index, wallet_id) in &batch {
                if used.contains(wallet_id) {
                    last_used = Some(*index);
                }
            }
            let first_unused = last_used.map_or(0, |index| index + 1);
            if end - first_unused >= gap {
                break;
            }
            start = end;
        }
        let next = last_used.map_or(0, |index| index + 1);
        state.next[slot(branch)] = state.next[slot(branch)].max(next);
    }
    wallet.extend(secrets, state)
}

fn show_backup(wallet: &Wallet) -> Result<(), String> {
    let file = wallet.read_file()?;
    if file.kind() != WalletKind::Master {
        return Err("a single-key v2 wallet has no itcseed backup; keep a copy of its file".into());
    }
    let mut state = wallet.state()?;
    let Secrets::Master(master) = wallet.unlock(&file, &mut state)? else {
        return Err("not a master wallet".into());
    };
    println!("{}", backup::encode(&master).as_str());
    state.save(&wallet.state_path())
}

// ------------------------------------------------------------ addresses

fn receive(wallet: &Wallet, label: Option<String>) -> Result<(), String> {
    let mut state = wallet.state()?;
    if state.kind == Kind::Single {
        let wallet_id = state.wallet_ids()[0];
        println!("{}", wallet.address(wallet_id));
        return Ok(());
    }
    let index = state.next[0];
    if index >= state.derived[0] {
        eprintln!("the stock of addresses is used up; the password is needed to derive more");
        let file = wallet.read_file()?;
        let secrets = wallet.unlock(&file, &mut state)?;
        state.next[0] += 1;
        wallet.extend(&secrets, &mut state)?;
        state.next[0] -= 1;
    }
    let record = state
        .keys
        .iter_mut()
        .find(|key| key.branch == 0 && key.index == index)
        .ok_or("damaged state file")?;
    if label.is_some() {
        record.label = label;
    }
    let wallet_id = parse_wallet_id(&record.wallet_id).ok_or("damaged state file")?;
    state.next[0] = index + 1;
    state.save(&wallet.state_path())?;
    println!("{}", wallet.address(wallet_id));
    Ok(())
}

fn addresses(wallet: &Wallet) -> Result<(), String> {
    let state = wallet.state()?;
    let node = wallet.node()?;
    let view = node.coins(&state.wallet_ids())?;
    let mut totals: HashMap<WalletId, u128> = HashMap::new();
    for coin in &view.confirmed {
        if !coin.spent_in_mempool {
            *totals.entry(coin.coin.output.wallet_id).or_default() +=
                u128::from(coin.coin.output.amount.as_satoshis());
        }
    }
    for key in &state.keys {
        let used = key.index < state.next[usize::from(key.branch.min(1))];
        let Some(wallet_id) = parse_wallet_id(&key.wallet_id) else {
            continue;
        };
        let balance = totals.get(&wallet_id).copied().unwrap_or(0);
        if !used && balance == 0 {
            continue;
        }
        println!(
            "{} {}/{} {:>20} {}",
            wallet.address(wallet_id),
            if key.branch == 0 { "receive" } else { "change" },
            key.index,
            itc(balance),
            key.label.as_deref().unwrap_or("")
        );
    }
    Ok(())
}

fn print_balance(wallet: &Wallet, node: &Node, state: &State) -> Result<(), String> {
    let view = node.coins(&state.wallet_ids())?;
    let (mut mature, mut immature, mut outgoing) = (0_u128, 0_u128, 0_u128);
    for coin in &view.confirmed {
        let value = u128::from(coin.coin.output.amount.as_satoshis());
        if coin.spent_in_mempool {
            outgoing += value;
        } else if coin.mature {
            mature += value;
        } else {
            immature += value;
        }
    }
    let unconfirmed: u128 = view
        .unconfirmed
        .iter()
        .map(|coin| u128::from(coin.output.amount.as_satoshis()))
        .sum();
    let _ = wallet;
    println!("spendable:   {} ITC", itc(mature));
    println!("immature:    {} ITC", itc(immature));
    println!("unconfirmed: {} ITC", itc(unconfirmed));
    if outgoing > 0 {
        println!("being spent: {} ITC", itc(outgoing));
    }
    Ok(())
}

fn balance(wallet: &Wallet) -> Result<(), String> {
    let state = wallet.state()?;
    let node = wallet.node()?;
    print_balance(wallet, &node, &state)
}

fn coins(wallet: &Wallet) -> Result<(), String> {
    let state = wallet.state()?;
    let node = wallet.node()?;
    let view = node.coins(&state.wallet_ids())?;
    let mut groups: HashMap<WalletId, Vec<&node::ViewCoin>> = HashMap::new();
    for coin in &view.confirmed {
        groups
            .entry(coin.coin.output.wallet_id)
            .or_default()
            .push(coin);
    }
    let mut keys: Vec<&WalletId> = groups.keys().collect();
    keys.sort();
    for wallet_id in keys {
        let group = &groups[wallet_id];
        let total: u128 = group
            .iter()
            .map(|coin| u128::from(coin.coin.output.amount.as_satoshis()))
            .sum();
        println!(
            "{}  {} ITC in {} coins",
            wallet.address(*wallet_id),
            itc(total),
            group.len()
        );
        for coin in group {
            let mut flags = Vec::new();
            if coin.coinbase {
                flags.push("coinbase");
            }
            if !coin.mature {
                flags.push("immature");
            }
            if coin.spent_in_mempool {
                flags.push("being spent");
            }
            println!(
                "    {} {:>20} {:>6} conf {}",
                coin_key(&coin.coin),
                itc_amount(coin.coin.output.amount),
                coin.confirmations,
                flags.join(", ")
            );
        }
    }
    for coin in &view.unconfirmed {
        println!(
            "unconfirmed {} {} {}",
            coin_key(coin),
            itc_amount(coin.output.amount),
            wallet.address(coin.output.wallet_id)
        );
    }
    Ok(())
}

// --------------------------------------------------------------- sending

struct SendOptions {
    payments: Vec<Output>,
    fee_rate: Option<u64>,
    target: u64,
    change_to_input: bool,
    yes: bool,
    dry_run: bool,
    allow_high_fee: bool,
}

/// The next change address, deriving more if the stock ran out.
fn change_wallet_id(
    wallet: &Wallet,
    secrets: Option<&Secrets>,
    state: &mut State,
) -> Result<WalletId, String> {
    if state.kind == Kind::Single {
        return Ok(state.wallet_ids()[0]);
    }
    if state.next[1] >= state.derived[1] {
        let secrets = secrets.ok_or("the change stock is used up")?;
        state.next[1] += 1;
        wallet.extend(secrets, state)?;
        state.next[1] -= 1;
    }
    let record = state
        .key_at(Branch::Change, state.next[1])
        .ok_or("damaged state file")?;
    parse_wallet_id(&record.wallet_id).ok_or_else(|| "damaged state file".into())
}

fn summary(wallet: &Wallet, plan: &Plan, payments: &[Output]) {
    for payment in payments {
        eprintln!(
            "  pay      {} ITC to {}",
            itc_amount(payment.amount),
            wallet.address(payment.wallet_id)
        );
    }
    if let Some(index) = plan.change_index {
        let change = plan.outputs[index];
        eprintln!(
            "  change   {} ITC to {}",
            itc_amount(change.amount),
            wallet.address(change.wallet_id)
        );
    }
    eprintln!(
        "  fee      {} ITC ({} sat/byte, {} bytes, {} keys, {} inputs)",
        itc_amount(plan.fee),
        plan.fee.as_satoshis() / plan.size.max(1) as u64,
        plan.size,
        plan.keys.len(),
        plan.inputs.len()
    );
}

fn high_fee(plan: &Plan, payments: &[Output], rate: u64) -> bool {
    let sent: u128 = payments
        .iter()
        .map(|payment| u128::from(payment.amount.as_satoshis()))
        .sum();
    u128::from(plan.fee.as_satoshis()) * 100 > sent * HIGH_FEE_PERCENT || rate > HIGH_FEE_RATE
}

/// Asks the confirmations of section 6.5. Returns false to abort.
fn approve(
    plan: &Plan,
    payments: &[Output],
    rate: u64,
    yes: bool,
    allow_high_fee: bool,
) -> Result<bool, String> {
    if high_fee(plan, payments, rate) && !allow_high_fee {
        if yes {
            return Err(
                "the fee is above 1% of the amount or 1000 sat/byte; pass --allow-high-fee".into(),
            );
        }
        if !confirm("The fee is HIGH (above 1% of the amount or 1000 sat/byte). Accept it? [y/N] ")?
        {
            return Ok(false);
        }
    }
    if yes {
        return Ok(true);
    }
    confirm("Send? [y/N] ")
}

fn sign(
    wallet: &Wallet,
    secrets: &Secrets,
    state: &State,
    plan: &Plan,
) -> Result<Transaction, String> {
    let mut pairs = Vec::with_capacity(plan.keys.len());
    for wallet_id in &plan.keys {
        pairs.push(wallet.key_pair(secrets, state, wallet_id)?);
    }
    plan.sign(&wallet.params.chain_id(), |wallet_id| {
        pairs
            .iter()
            .find(|pair| pair.public_key.wallet_id() == *wallet_id)
    })
    .map_err(|error| error.to_string())
}

fn record(
    wallet: &Wallet,
    plan: &Plan,
    payments: &[Output],
    transaction: &Transaction,
    txid: &str,
) -> SentRecord {
    SentRecord {
        txid: txid.to_owned(),
        transaction: encode_base64url(&transaction.to_bytes()),
        inputs: plan.inputs.iter().map(coin_key).collect(),
        payments: payments
            .iter()
            .map(|payment| PaymentRecord {
                address: wallet.address(payment.wallet_id),
                amount_sat: payment.amount.as_satoshis().to_string(),
            })
            .collect(),
        change_wallet_id: plan
            .change_index
            .map(|index| plan.outputs[index].wallet_id.to_string()),
        fee_sat: plan.fee.as_satoshis().to_string(),
        size: plan.size,
        time: now(),
        status: Status::Mempool,
        replaced_by: None,
    }
}

fn send(wallet: &Wallet, options: &SendOptions) -> Result<(), String> {
    let mut state = wallet.state()?;
    let node = wallet.node()?;
    let view = node.coins(&state.wallet_ids())?;
    let rate = match options.fee_rate {
        Some(rate) => rate,
        None => node.fee_rate(options.target)?.0,
    };
    if rate == 0 {
        return Err("the fee rate must be positive".into());
    }
    let file = wallet.read_file()?;
    // A provisional change address keeps the size exact; the real one is
    // the same unless the stock runs out, which needs the password anyway.
    let change = if options.change_to_input {
        ChangeTo::LargestInput
    } else {
        ChangeTo::Wallet(
            change_wallet_id(wallet, None, &mut state)
                .unwrap_or(WalletId::new(Hash256::new([0; 32]))),
        )
    };
    let spendable = view.spendable();
    let mut plan = builder::plan_payment(&Payment {
        coins: &spendable,
        required: &[],
        outputs: &options.payments,
        fee_rate: rate,
        change,
    })
    .map_err(|error| error.to_string())?;
    summary(wallet, &plan, &options.payments);
    if !options.dry_run
        && !approve(
            &plan,
            &options.payments,
            rate,
            options.yes,
            options.allow_high_fee,
        )?
    {
        return Err("cancelled".into());
    }
    let secrets = wallet.unlock(&file, &mut state)?;
    let uses_new_change = matches!(change, ChangeTo::Wallet(_)) && plan.change_index.is_some();
    if uses_new_change {
        let real = change_wallet_id(wallet, Some(&secrets), &mut state)?;
        if let Some(index) = plan.change_index {
            plan.outputs[index].wallet_id = real;
        }
    }
    let transaction = sign(wallet, &secrets, &state, &plan)?;
    if options.dry_run {
        println!("{}", encode_base64url(&transaction.to_bytes()));
        return Ok(());
    }
    let txid = node.send(&transaction)?;
    if uses_new_change {
        state.next[1] += 1;
        wallet.extend(&secrets, &mut state)?;
    }
    state.sent.push(record(
        wallet,
        &plan,
        &options.payments,
        &transaction,
        &txid,
    ));
    state.save(&wallet.state_path())?;
    println!("{txid}");
    Ok(())
}

fn consolidate(
    wallet: &Wallet,
    max_keys: usize,
    fee_rate: Option<u64>,
    yes: bool,
) -> Result<(), String> {
    if !(2..=MAX_KEYS_PER_TX).contains(&max_keys) {
        return Err(format!("--max-keys must be 2 to {MAX_KEYS_PER_TX}"));
    }
    let mut state = wallet.state()?;
    let node = wallet.node()?;
    let view = node.coins(&state.wallet_ids())?;
    let rate = match fee_rate {
        Some(rate) => rate,
        None => node.fee_rate(6)?.0,
    };
    let mut groups: HashMap<WalletId, Vec<Coin>> = HashMap::new();
    for coin in view.spendable() {
        groups.entry(coin.output.wallet_id).or_default().push(coin);
    }
    if groups.len() < 2 {
        return Err("nothing to consolidate: the coins are under one key already".into());
    }
    // The smallest groups first: they are the ones that cost most to spend.
    let mut ordered: Vec<(WalletId, Vec<Coin>)> = groups.into_iter().collect();
    ordered.sort_by_key(|(wallet_id, coins)| {
        (
            coins
                .iter()
                .map(|coin| coin.output.amount.as_satoshis())
                .sum::<u64>(),
            *wallet_id,
        )
    });
    let mut selected: Vec<Coin> = Vec::new();
    for (_, coins) in ordered.into_iter().take(max_keys) {
        if builder::transaction_size(selected.len() + coins.len(), 1, max_keys) > MAX_TX_BYTES {
            break;
        }
        selected.extend(coins);
    }
    let file = wallet.read_file()?;
    let destination =
        change_wallet_id(wallet, None, &mut state).unwrap_or(WalletId::new(Hash256::new([0; 32])));
    let mut plan =
        builder::plan_sweep(&selected, destination, rate).map_err(|error| error.to_string())?;
    summary(wallet, &plan, &[]);
    if !yes && !confirm("Consolidate? [y/N] ")? {
        return Err("cancelled".into());
    }
    let secrets = wallet.unlock(&file, &mut state)?;
    let real = change_wallet_id(wallet, Some(&secrets), &mut state)?;
    plan.outputs[0].wallet_id = real;
    let transaction = sign(wallet, &secrets, &state, &plan)?;
    let txid = node.send(&transaction)?;
    if state.kind == Kind::Master {
        state.next[1] += 1;
        wallet.extend(&secrets, &mut state)?;
    }
    state
        .sent
        .push(record(wallet, &plan, &[], &transaction, &txid));
    state.save(&wallet.state_path())?;
    println!("{txid}");
    Ok(())
}

/// Updates the status of transactions still marked as in the mempool.
fn refresh(node: &Node, state: &mut State) -> Result<(), String> {
    for sent in state
        .sent
        .iter_mut()
        .filter(|sent| sent.status == Status::Mempool)
    {
        if node.in_mempool(&sent.txid)? {
            continue;
        }
        let mut any_unspent = false;
        for input in &sent.inputs {
            if node.is_unspent(input)? {
                any_unspent = true;
                break;
            }
        }
        sent.status = if any_unspent {
            Status::Dropped
        } else {
            Status::Confirmed
        };
    }
    Ok(())
}

fn bumpfee(wallet: &Wallet, txid: &str, fee_rate: Option<u64>, yes: bool) -> Result<(), String> {
    let mut state = wallet.state()?;
    let node = wallet.node()?;
    refresh(&node, &mut state)?;
    let position = state
        .sent
        .iter()
        .position(|sent| sent.txid == txid)
        .ok_or("this wallet did not send that transaction")?;
    let original = state.sent[position].clone();
    if original.status != Status::Mempool {
        return Err(format!(
            "the transaction is no longer in the mempool ({:?})",
            original.status
        ));
    }
    let old_fee: u64 = original.fee_sat.parse().map_err(|_| "damaged state file")?;
    let (estimate, minimum) = node.fee_rate(6)?;
    // Replacement rules: a higher rate, and the old fee plus relay of the
    // new transaction.
    let floor = old_fee.div_ceil(original.size.max(1) as u64) + minimum;
    let rate = fee_rate.unwrap_or(estimate).max(floor);

    let payments: Vec<Output> = original
        .payments
        .iter()
        .map(|payment| {
            Ok(Output {
                amount: parse_sat(&payment.amount_sat).map_err(|_| "damaged state file")?,
                wallet_id: Address::from_str(&payment.address)
                    .map_err(|_| "damaged state file")?
                    .wallet_id(),
            })
        })
        .collect::<Result<_, String>>()?;
    let view = node.coins(&state.wallet_ids())?;
    let own: HashSet<&str> = original.inputs.iter().map(String::as_str).collect();
    let coins: Vec<Coin> = view
        .confirmed
        .iter()
        .filter(|coin| {
            coin.mature && (!coin.spent_in_mempool || own.contains(coin_key(&coin.coin).as_str()))
        })
        .map(|coin| coin.coin)
        .collect();
    let required: Vec<_> = view
        .confirmed
        .iter()
        .filter(|coin| own.contains(coin_key(&coin.coin).as_str()))
        .map(|coin| coin.coin.outpoint)
        .collect();
    if required.len() != original.inputs.len() {
        return Err("some inputs of the transaction are gone; it may have confirmed".into());
    }
    let file = wallet.read_file()?;
    let change = match original
        .change_wallet_id
        .as_deref()
        .and_then(parse_wallet_id)
    {
        Some(wallet_id) => ChangeTo::Wallet(wallet_id),
        None => ChangeTo::Wallet(
            change_wallet_id(wallet, None, &mut state)
                .unwrap_or(WalletId::new(Hash256::new([0; 32]))),
        ),
    };
    let plan = if payments.is_empty() {
        // A consolidation: sweep the same coins at the higher rate.
        let destination = original
            .change_wallet_id
            .as_deref()
            .and_then(parse_wallet_id)
            .ok_or("damaged state file")?;
        let selected: Vec<Coin> = coins
            .iter()
            .filter(|coin| own.contains(coin_key(coin).as_str()))
            .copied()
            .collect();
        builder::plan_sweep(&selected, destination, rate)
    } else {
        builder::plan_payment(&Payment {
            coins: &coins,
            required: &required,
            outputs: &payments,
            fee_rate: rate,
            change,
        })
    }
    .map_err(|error| error.to_string())?;
    summary(wallet, &plan, &payments);
    if !yes && !confirm("Replace? [y/N] ")? {
        return Err("cancelled".into());
    }
    let secrets = wallet.unlock(&file, &mut state)?;
    let transaction = sign(wallet, &secrets, &state, &plan)?;
    let new_txid = node.send(&transaction)?;
    state.sent[position].status = Status::Replaced;
    state.sent[position].replaced_by = Some(new_txid.clone());
    state
        .sent
        .push(record(wallet, &plan, &payments, &transaction, &new_txid));
    state.save(&wallet.state_path())?;
    println!("{new_txid}");
    Ok(())
}

fn history(wallet: &Wallet) -> Result<(), String> {
    let mut state = wallet.state()?;
    let node = wallet.node()?;
    refresh(&node, &mut state)?;
    state.save(&wallet.state_path())?;
    for sent in &state.sent {
        let paid: u128 = sent
            .payments
            .iter()
            .filter_map(|payment| payment.amount_sat.parse::<u128>().ok())
            .sum();
        let status = match sent.status {
            Status::Mempool => "mempool".to_owned(),
            Status::Confirmed => "confirmed".to_owned(),
            Status::Dropped => "dropped".to_owned(),
            Status::Replaced => {
                format!("replaced by {}", sent.replaced_by.as_deref().unwrap_or("?"))
            }
        };
        let fee: u128 = sent.fee_sat.parse().unwrap_or(0);
        println!(
            "{} {:>20} fee {} {}",
            sent.txid,
            itc(paid),
            itc(fee),
            status
        );
    }
    Ok(())
}

fn rescan(wallet: &Wallet, gap: u32) -> Result<(), String> {
    let mut state = wallet.state()?;
    let node = wallet.node()?;
    let file = wallet.read_file()?;
    let secrets = wallet.unlock(&file, &mut state)?;
    scan(wallet, &node, &secrets, &mut state, gap)?;
    state.save(&wallet.state_path())?;
    print_balance(wallet, &node, &state)
}

fn passwd(wallet: &Wallet) -> Result<(), String> {
    let mut state = wallet.state()?;
    let file = wallet.read_file()?;
    let secrets = wallet.unlock(&file, &mut state)?;
    let password = new_password()?;
    let generation = file.generation() + 1;
    let next = match &secrets {
        Secrets::Master(master) => EncryptedWallet::encrypt_master(master, &password, generation),
        Secrets::Single(pair) => {
            let copy = copy_key(pair)?;
            itacoin_wallet::Wallet::from_private_key(copy.private_key)
                .and_then(|single| single.encrypt(&password, generation))
        }
    }
    .map_err(|error| error.to_string())?;
    next.replace(&wallet.file())
        .map_err(|error| error.to_string())?;
    state.generation = generation;
    state.save(&wallet.state_path())?;
    println!("Password changed.");
    Ok(())
}

fn info(wallet: &Wallet) -> Result<(), String> {
    let file = wallet.read_file()?;
    let state = State::load(&wallet.state_path())?;
    println!("wallet:      {}", wallet.dir.display());
    println!(
        "kind:        {}",
        match file.kind() {
            WalletKind::Master => "master secret (ITCW v3)",
            WalletKind::SingleKey => "single key (ITCW v2)",
        }
    );
    println!("fingerprint: {}", file.identity());
    println!("generation:  {}", file.generation());
    println!("network:     {}", network_name(wallet.network));
    match state {
        Some(state) => {
            println!(
                "addresses:   {} receiving and {} change in use",
                state.next[0], state.next[1]
            );
            println!("derived:     {} + {}", state.derived[0], state.derived[1]);
            println!("sent:        {} transactions", state.sent.len());
        }
        None => println!("state:       not initialized on this network yet"),
    }
    Ok(())
}

fn import_v2(wallet: &Wallet, path: &Path) -> Result<(), String> {
    let source =
        EncryptedWallet::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if source.kind() != WalletKind::SingleKey {
        return Err("that file is not a v2 single-key wallet".into());
    }
    let password = password("Password of the v2 wallet: ")?;
    let single = source
        .decrypt(&password)
        .map_err(|_| "wrong password or damaged wallet file")?;
    prepare_dir(wallet)?;
    source
        .write_new(&wallet.file())
        .map_err(|error| format!("could not write the wallet: {error}"))?;
    let mut state = State::new(
        network_name(wallet.network),
        Kind::Single,
        source.identity(),
        source.generation(),
    );
    state.add_key(single.wallet_id(), Branch::Receive, 0);
    state.derived = [1, 0];
    state.next = [1, 0];
    state.save(&wallet.state_path())?;
    println!("Imported. Address: {}", wallet.address(single.wallet_id()));
    Ok(())
}
