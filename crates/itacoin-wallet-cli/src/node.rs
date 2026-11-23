//! The node's RPC as the wallet uses it (section 7 of
//! `docs/WALLET_PROPOSAL.md`).

use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
};

use itacoin_codec::Encode;
use itacoin_primitives::{Address, Amount, Network, TransactionId, WalletId};
use itacoin_rpc::{
    Client, ClientError, Cookie, default_rpc_port, network_name,
    request::code,
    text::{decode_hash, encode_base64url, parse_sat},
};
use itacoin_transaction::{OutPoint, Output, Transaction};
use itacoin_wallet::builder::Coin;
use serde_json::{Value, json};

/// Addresses per `listunspent` call.
const ADDRESS_CHUNK: usize = 100;

/// A confirmed coin as the node reports it.
#[derive(Clone, Copy, Debug)]
pub struct ViewCoin {
    /// The coin.
    pub coin: Coin,
    /// Confirmations.
    pub confirmations: u64,
    /// Whether a coinbase created it.
    pub coinbase: bool,
    /// Whether it can be spent now.
    pub mature: bool,
    /// Whether a mempool transaction already spends it.
    pub spent_in_mempool: bool,
}

/// Every coin of a set of addresses.
#[derive(Clone, Debug, Default)]
pub struct CoinView {
    /// Confirmed coins.
    pub confirmed: Vec<ViewCoin>,
    /// Outputs of mempool transactions, not yet confirmed.
    pub unconfirmed: Vec<Coin>,
}

impl CoinView {
    /// Coins a new transaction may spend.
    #[must_use]
    pub fn spendable(&self) -> Vec<Coin> {
        self.confirmed
            .iter()
            .filter(|coin| coin.mature && !coin.spent_in_mempool)
            .map(|coin| coin.coin)
            .collect()
    }
}

/// A connection to the node.
pub struct Node {
    client: Client,
    network: Network,
}

fn outpoint_text(outpoint: &OutPoint) -> String {
    format!("{}:{}", outpoint.txid, outpoint.index)
}

fn parse_coin(value: &Value) -> Option<Coin> {
    Some(Coin {
        outpoint: OutPoint {
            txid: TransactionId::new(decode_hash(value["txid"].as_str()?).ok()?),
            index: u16::try_from(value["index"].as_u64()?).ok()?,
        },
        output: Output {
            amount: parse_sat(value["amount_sat"].as_str()?).ok()?,
            wallet_id: WalletId::new(decode_hash(value["wallet_id"].as_str()?).ok()?),
        },
    })
}

impl Node {
    /// Connects with the cookie in `<base>/<network>/` or with `--rpc-user`
    /// and `ITACOIN_RPC_PASSWORD`.
    pub fn connect(
        base: &Path,
        network: Network,
        rpc_connect: Option<&str>,
        rpc_user: Option<&str>,
    ) -> Result<Self, String> {
        let addr: SocketAddr = match rpc_connect {
            Some(text) => text
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or("invalid --rpc-connect")?,
            None => SocketAddr::from(([127, 0, 0, 1], default_rpc_port(network))),
        };
        if !addr.ip().is_loopback() {
            eprintln!(
                "warning: {addr} is not this machine; its operator sees every address of this \
                 wallet and could lie about balances (but cannot spend)"
            );
        }
        let client = match rpc_user {
            Some(user) => {
                let password = zeroize::Zeroizing::new(
                    std::env::var("ITACOIN_RPC_PASSWORD")
                        .map_err(|_| "set ITACOIN_RPC_PASSWORD for --rpc-user")?,
                );
                Client::new(addr, user, &password)
            }
            None => {
                let path = base.join(network_name(network)).join(".cookie");
                let (user, password) = Cookie::read(&path).map_err(|error| {
                    format!(
                        "could not read the node cookie {} (is itacoin-node running?): {error}",
                        path.display()
                    )
                })?;
                Client::new(addr, &user, &password)
            }
        };
        Ok(Self { client, network })
    }

    fn call(&self, method: &str, params: Vec<Value>) -> Result<Value, ClientError> {
        self.client.call(method, params)
    }

    fn call_text(&self, method: &str, params: Vec<Value>) -> Result<Value, String> {
        self.call(method, params)
            .map_err(|error| format!("{method}: {error}"))
    }

    /// Every coin of `wallets`, confirmed and unconfirmed.
    pub fn coins(&self, wallets: &[WalletId]) -> Result<CoinView, String> {
        let mut view = CoinView::default();
        for chunk in wallets.chunks(ADDRESS_CHUNK) {
            let addresses: Vec<String> = chunk
                .iter()
                .map(|wallet| Address::new(self.network, *wallet).to_string())
                .collect();
            let mut cursor = Value::Null;
            loop {
                let page = self.call_text(
                    "listunspent",
                    vec![json!(addresses), cursor.clone(), json!(1_000), json!(true)],
                )?;
                for item in page["unspent"].as_array().into_iter().flatten() {
                    let coin = parse_coin(item).ok_or("malformed listunspent answer")?;
                    view.confirmed.push(ViewCoin {
                        coin,
                        confirmations: item["confirmations"].as_u64().unwrap_or(0),
                        coinbase: item["coinbase"].as_bool().unwrap_or(false),
                        mature: item["mature"].as_bool().unwrap_or(false),
                        spent_in_mempool: item["spent_in_mempool"].as_bool().unwrap_or(false),
                    });
                }
                if cursor.is_null() {
                    for item in page["unconfirmed"].as_array().into_iter().flatten() {
                        view.unconfirmed
                            .push(parse_coin(item).ok_or("malformed listunspent answer")?);
                    }
                }
                if page["next"].is_null() {
                    break;
                }
                cursor = page["next"].clone();
            }
        }
        Ok(view)
    }

    /// The fee rate for `blocks` and the node's minimum relay rate.
    pub fn fee_rate(&self, blocks: u64) -> Result<(u64, u64), String> {
        let estimate = self.call_text("estimatefee", vec![json!(blocks)])?;
        let rate = estimate["fee_rate"]
            .as_u64()
            .ok_or("malformed estimatefee answer")?;
        let minimum = estimate["min_fee_rate"].as_u64().unwrap_or(1);
        Ok((rate, minimum))
    }

    /// Sends a signed transaction and returns its txid.
    pub fn send(&self, transaction: &Transaction) -> Result<String, String> {
        let result = self.call_text(
            "sendrawtransaction",
            vec![json!(encode_base64url(&transaction.to_bytes()))],
        )?;
        result
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "malformed sendrawtransaction answer".into())
    }

    /// Whether `txid` is in the mempool.
    pub fn in_mempool(&self, txid: &str) -> Result<bool, String> {
        match self.call("getmempoolentry", vec![json!(txid)]) {
            Ok(_) => Ok(true),
            Err(ClientError::Rpc { code: c, .. }) if c == code::NOT_FOUND => Ok(false),
            Err(error) => Err(format!("getmempoolentry: {error}")),
        }
    }

    /// Whether `outpoint` (`txid:index`) is still unspent in the chain.
    pub fn is_unspent(&self, outpoint: &str) -> Result<bool, String> {
        let (txid, index) = outpoint.split_once(':').ok_or("malformed outpoint")?;
        let index: u64 = index.parse().map_err(|_| "malformed outpoint")?;
        Ok(!self
            .call_text("gettxout", vec![json!(txid), json!(index)])?
            .is_null())
    }
}

/// `txid:index` of a coin.
#[must_use]
pub fn coin_key(coin: &Coin) -> String {
    outpoint_text(&coin.outpoint)
}

/// Formats satoshis as ITC with eight decimals.
#[must_use]
pub fn itc(satoshis: u128) -> String {
    let coin = u128::from(itacoin_primitives::COIN);
    format!("{}.{:08}", satoshis / coin, satoshis % coin)
}

/// Formats an amount as ITC.
#[must_use]
pub fn itc_amount(amount: Amount) -> String {
    itc(u128::from(amount.as_satoshis()))
}
