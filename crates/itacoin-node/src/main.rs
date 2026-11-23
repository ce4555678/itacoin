//! The ITACOIN full node binary (section 6 of `docs/NODE_PROPOSAL.md`):
//! P2P network, JSON-RPC and the embedded miner in one process.

use std::{process::ExitCode, time::Instant};

use clap::Parser;
use itacoin_miner::Miner;
use itacoin_network::node::{NodeConfig, NodeHandle, start};
use itacoin_rpc::{Context, Cookie, Credentials, MinerControl, RpcConfig, serve};
use tokio::sync::{mpsc, watch};
use tracing_subscriber::EnvFilter;

mod config;
mod mining;

use config::{CONFIG_FILE, Cli, FileConfig, Settings};

fn main() -> ExitCode {
    // Protections first, before any file is opened (V-07).
    let warnings = itacoin_process::harden();
    let cli = Cli::parse();
    match prepare(cli) {
        Ok((settings, lock)) => {
            init_logging(&settings.log_level);
            for warning in warnings {
                tracing::warn!("{warning}");
            }
            let result = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("itacoin")
                .build()
                .map_err(|error| format!("could not start the runtime: {error}"))
                .and_then(|runtime| runtime.block_on(run(settings)));
            drop(lock);
            match result {
                Ok(()) => ExitCode::SUCCESS,
                Err(message) => {
                    tracing::error!("{message}");
                    ExitCode::FAILURE
                }
            }
        }
        Err(message) => {
            eprintln!("itacoin-node: {message}");
            ExitCode::FAILURE
        }
    }
}

fn prepare(cli: Cli) -> Result<(Settings, itacoin_process::DirLock), String> {
    let (network, data_dir) = config::network_and_dir(&cli)?;
    config::params_for(network)?;
    itacoin_process::create_data_dir(&data_dir)
        .map_err(|error| format!("could not create {}: {error}", data_dir.display()))?;
    let lock = itacoin_process::DirLock::acquire(&data_dir)?;
    let file = FileConfig::load(&data_dir.join(CONFIG_FILE))?;
    let settings = config::resolve(cli, file, network, data_dir)?;
    Ok((settings, lock))
}

fn init_logging(level: &str) {
    let filter = EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();
}

/// Resolves on SIGINT or SIGTERM.
async fn os_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate = signal(SignalKind::terminate()).ok();
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("interrupt received"),
            () = async {
                match terminate.as_mut() {
                    Some(terminate) => { terminate.recv().await; }
                    None => std::future::pending::<()>().await,
                }
            } => tracing::info!("terminate received"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("interrupt received");
    }
}

async fn run(settings: Settings) -> Result<(), String> {
    let started = Instant::now();
    let params = settings.params;
    let mut node_config = NodeConfig::new(params, settings.data_dir.clone());
    node_config.listen = settings.listen;
    node_config.connect.clone_from(&settings.connect);
    node_config.add_nodes.clone_from(&settings.add_nodes);
    if let Some(max) = settings.max_inbound {
        node_config.max_inbound = max;
    }
    let handle = start(node_config)
        .await
        .map_err(|error| format!("could not start the node: {error:?}"))?;

    let verified = handle
        .call(|core| {
            core.chain()
                .store()
                .verify()
                .map_err(|error| error.to_string())
        })
        .await
        .unwrap_or_else(|| Err("the node stopped".into()));
    if let Err(error) = verified {
        handle.shutdown().await;
        return Err(format!(
            "the chain state failed verification ({error}); it may need a reindex"
        ));
    }
    let tip = handle.tip().await;
    tracing::info!(
        "itacoin-node {} on {:?}, tip height {}",
        env!("CARGO_PKG_VERSION"),
        params.network,
        tip.map_or(0, |tip| tip.height)
    );
    if let Some(addr) = handle.local_addr() {
        tracing::info!("P2P listening on {addr}");
    }
    #[cfg(feature = "mainnet")]
    if params.network == itacoin_primitives::Network::Mainnet {
        tracing::warn!("mainnet build: the handshake and ML-DSA reviews are still pending");
    }

    let (found_tx, found_rx) = mpsc::unbounded_channel();
    let miner = Miner::new(found_tx);
    let control = settings.mining.map(|mining| MinerControl {
        miner: miner.clone(),
        default_threads: mining.threads,
    });

    let cookie_path = settings.data_dir.join(".cookie");
    let cookie = Cookie::create(&cookie_path)
        .map_err(|error| format!("could not write {}: {error}", cookie_path.display()))?;
    let (stop_tx, mut stop_rx) = watch::channel(false);
    let context = Context {
        handle: handle.clone(),
        params,
        miner: control,
        started,
        stop: stop_tx.clone(),
        data_dir: settings.data_dir.clone(),
        rpc_addrs: Vec::new(),
    };
    let server = match serve(
        RpcConfig {
            binds: settings.rpc_binds.clone(),
            allow: settings.rpc_allow.clone(),
            credentials: Credentials {
                cookie: Some(cookie),
                fixed: settings.rpc_auth.clone(),
            },
        },
        context,
    )
    .await
    {
        Ok(server) => server,
        Err(error) => {
            handle.shutdown().await;
            let _ = std::fs::remove_file(&cookie_path);
            return Err(error.to_string());
        }
    };
    for addr in server.local_addrs() {
        tracing::info!("RPC listening on {addr}");
    }

    let controller = settings.mining.map(|mining| {
        if mining.start {
            miner.set_threads(mining.threads);
        }
        tokio::spawn(mining::run(
            handle.clone(),
            miner.clone(),
            mining.payout,
            params.chain_id(),
            mining.without_peers,
            found_rx,
            stop_tx.subscribe(),
        ))
    });

    tokio::select! {
        () = os_signal() => {}
        _ = stop_rx.changed() => tracing::info!("stop requested over RPC"),
    }
    let _ = stop_tx.send(true);
    // A second signal while shutting down exits at once; redb is
    // transactional, so at worst the peer files are lost.
    tokio::spawn(async {
        os_signal().await;
        eprintln!("itacoin-node: second signal, exiting now");
        std::process::exit(130);
    });

    shutdown(server, miner, controller, &handle).await;
    let _ = std::fs::remove_file(&cookie_path);
    tracing::info!("stopped");
    Ok(())
}

/// Section 6.5: RPC, then the miner, then the network and the database.
async fn shutdown(
    server: itacoin_rpc::RpcServer,
    miner: Miner,
    controller: Option<tokio::task::JoinHandle<()>>,
    handle: &NodeHandle,
) {
    server.shutdown().await;
    let _ = tokio::task::spawn_blocking(move || miner.shutdown()).await;
    if let Some(controller) = controller {
        controller.abort();
        let _ = controller.await;
    }
    handle.shutdown().await;
}
