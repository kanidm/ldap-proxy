#![deny(warnings)]
#![warn(unused_extern_crates)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use clap::Parser;
use concread::arcache::ARCacheBuilder;
use ldap3_proto::LdapCodec;
use ldap_proxy::{proxy, AddrInfoSource, AppState, Config};
use openssl::ssl::{Ssl, SslAcceptor, SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_openssl::SslStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::span;
use tracing_forest::{traits::*, util::*};
// use tracing_forest::{traits::*, util::*};

const DEFAULT_CONFIG_PATH: &str = "/etc/kanidm/ldap-proxy";

#[derive(Debug, clap::Parser)]
struct Opt {
    #[clap(short, long, env = "LDAP_PROXY_DEBUG")]
    debug: bool,

    #[clap(value_parser, short, long, default_value_os_t = DEFAULT_CONFIG_PATH.into(), env="LDAP_PROXY_CONFIG_PATH")]
    config: PathBuf,
}

async fn ldaps_tls_acceptor(
    tcpstream: TcpStream,
    client_socket_addr: SocketAddr,
    tls_parms: SslAcceptor,
    app_state: Arc<AppState>,
) {
    use haproxy_protocol::{ProxyHdrV2, RemoteAddress};
    let span = span!(Level::DEBUG, "tls_accept");
    let _enter = span.enter();

    let max_incoming_ber_size = app_state.max_incoming_ber_size;

    let (tcpstream, reported_socket_addr) = match app_state.remote_ip_addr_info {
        AddrInfoSource::None => (tcpstream, None),
        AddrInfoSource::ProxyV2 => match ProxyHdrV2::parse_from_read(tcpstream).await {
            Ok((tcpstream, hdr)) => {
                let remote_socket_addr = match hdr.to_remote_addr() {
                    RemoteAddress::Local => {
                        debug!("haproxy check");
                        return;
                    }
                    RemoteAddress::TcpV4 { src, dst: _ } => SocketAddr::from(src),
                    RemoteAddress::TcpV6 { src, dst: _ } => SocketAddr::from(src),
                    remote_addr => {
                        error!(?remote_addr, "remote address in proxy header is invalid");
                        return;
                    }
                };

                (tcpstream, Some(remote_socket_addr))
            }
            Err(err) => {
                error!(?err, "Unable to process proxy v2 header");
                return;
            }
        },
    };

    debug!(remote_addr_source = ?app_state.remote_ip_addr_info, ?reported_socket_addr);

    let mut tlsstream = match Ssl::new(tls_parms.context())
        .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
    {
        Ok(ta) => ta,
        Err(e) => {
            error!("LDAP TLS setup error -> {:?}", e);
            return;
        }
    };
    if let Err(e) = SslStream::accept(Pin::new(&mut tlsstream)).await {
        error!("LDAP TLS accept error -> {:?}", e);
        return;
    };
    let (r, w) = tokio::io::split(tlsstream);
    let r = FramedRead::new(r, LdapCodec::new(max_incoming_ber_size));
    let w = FramedWrite::new(w, LdapCodec::new(max_incoming_ber_size));

    tokio::spawn(proxy::client_process(
        r,
        w,
        client_socket_addr,
        reported_socket_addr,
        app_state,
    ));
}

async fn ldaps_acceptor(
    listener: TcpListener,
    tls_parms: SslAcceptor,
    mut broadcast_rx: broadcast::Receiver<bool>,
    app_state: Arc<AppState>,
) {
    loop {
        tokio::select! {
            _ = broadcast_rx.recv() => {
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((tcpstream, client_socket_addr)) => {
                        let c_app_state = app_state.clone();
                        tokio::spawn(ldaps_tls_acceptor( tcpstream, client_socket_addr, tls_parms.clone(), c_app_state ));
                    }
                    Err(e) => {
                        error!("LDAP acceptor error, continuing -> {:?}", e);
                    }
                }
            }
        }
    }
    debug!("Stopped ldaps acceptor");
}

async fn setup(opt: &Opt) {
    info!("Starting ldap-proxy");

    let mut f = match File::open(&opt.config) {
        Ok(f) => f,
        Err(e) => {
            error!(
                "Unable to open config file '{}' [{:?}] 🥺",
                &opt.config.display(),
                e
            );
            return;
        }
    };

    let mut contents = String::new();
    if let Err(e) = f.read_to_string(&mut contents) {
        error!(
            "unable to read config contents from '{}' {:?}",
            &opt.config.display(),
            e
        );
        return;
    };

    let sync_config: Config = match toml::from_str(contents.as_str()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "unable to parse config from '{}' {:?}",
                &opt.config.display(),
                e
            );
            return;
        }
    };

    debug!(?sync_config);

    // Do we need to re-process the config to a different shape?

    // Setup the broadcast system.
    let (broadcast_tx, broadcast_rx) = broadcast::channel(1);

    // Let the listening port ready.
    let listener = match TcpListener::bind(&sync_config.bind).await {
        Ok(l) => l,
        Err(e) => {
            error!(
                "Could not bind to LDAP server address {} -> {:?}",
                sync_config.bind, e
            );
            return;
        }
    };

    // Setup the data for the client handles.

    let url = sync_config.ldap_url;

    match url.scheme() {
        "ldaps" => {}
        _ => {
            error!("Unable to proceed. LDAPS is required in remote ldap_url");
            return;
        }
    };

    let hostname = match url.host_str() {
        Some(s) => s,
        None => {
            error!("Unable to determine hostname from url");
            return;
        }
    };

    let addrs = match url.socket_addrs(|| Some(636)) {
        Ok(a) => a,
        Err(e) => {
            error!(?e, "url address resolver error");
            return;
        }
    };

    if addrs.is_empty() {
        error!("url address resolved to no addresses");
        return;
    }

    let mut tls_builder = match SslConnector::builder(SslMethod::tls_client()) {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to create tls client -> {:?}", e);
            return;
        }
    };

    let cert_store = tls_builder.cert_store_mut();
    let mut file = match File::open(&sync_config.ldap_ca) {
        Ok(f) => f,
        Err(e) => {
            error!(?e, "Unable to open {:?}", &sync_config.ldap_ca);
            return;
        }
    };

    let mut pem = Vec::new();
    if let Err(e) = file.read_to_end(&mut pem) {
        error!(?e, "Unable to read {:?}", &sync_config.ldap_ca);
        return;
    }

    let ca_cert = match X509::from_pem(pem.as_slice()) {
        Ok(c) => c,
        Err(e) => {
            error!(?e, "openssl");
            return;
        }
    };

    if let Err(e) = cert_store.add_cert(ca_cert).map(|()| {
        debug!("Added {:?} to cert store", &sync_config.ldap_ca);
    }) {
        error!(?e, "openssl");
        return;
    };

    let verify_param = tls_builder.verify_param_mut();
    if let Err(e) = verify_param.set_host(hostname) {
        error!(?e, "openssl");
        return;
    }

    // None for no cert verification
    tls_builder.set_verify(SslVerifyMode::PEER);

    let tls_params = tls_builder.build();

    let Some(cache) = ARCacheBuilder::new()
        .set_size(sync_config.cache_bytes, 0)
        .build()
    else {
        error!("Unable to build query cache");
        return;
    };

    let cache_entry_timeout = Duration::from_secs(sync_config.cache_entry_timeout);

    let max_incoming_ber_size = sync_config.max_incoming_ber_size;
    let max_proxy_ber_size = sync_config.max_proxy_ber_size;
    let allow_all_bind_dns = sync_config.allow_all_bind_dns;
    let remote_ip_addr_info = sync_config.remote_ip_addr_info;

    let app_state = Arc::new(AppState {
        tls_params,
        addrs,
        binddn_map: sync_config.binddn_map.clone(),
        cache,
        cache_entry_timeout,
        max_incoming_ber_size,
        max_proxy_ber_size,
        allow_all_bind_dns,
        remote_ip_addr_info,
    });

    // Setup the TLS server parameters
    let mut tls_builder = match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()) {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to create tls acceptor -> {:?}", e);
            return;
        }
    };

    if let Err(e) = tls_builder.set_certificate_chain_file(&sync_config.tls_chain) {
        error!("Unable to load certificate chain -> {:?}", e);
        return;
    }

    if let Err(e) = tls_builder.set_private_key_file(&sync_config.tls_key, SslFiletype::PEM) {
        error!("Unable to load private key -> {:?}", e);
        return;
    }

    if let Err(e) = tls_builder.check_private_key() {
        error!("Unable to validate private key -> {:?}", e);
        return;
    }

    // Done!
    let tls_server_params = tls_builder.build();

    // Setup the acceptor.
    let acceptor = tokio::spawn(async move {
        ldaps_acceptor(listener, tls_server_params, broadcast_rx, app_state).await
    });

    // Finally, block on the signal handler.
    loop {
        tokio::select! {
            Ok(()) = tokio::signal::ctrl_c() => {
                break
            }
            Some(()) = async move {
                let sigterm = tokio::signal::unix::SignalKind::terminate();
                #[allow(clippy::unwrap_used)]
                tokio::signal::unix::signal(sigterm).unwrap().recv().await
            } => {
                break
            }
            Some(()) = async move {
                let sigterm = tokio::signal::unix::SignalKind::alarm();
                #[allow(clippy::unwrap_used)]
                tokio::signal::unix::signal(sigterm).unwrap().recv().await
            } => {
                // Ignore
            }
            Some(()) = async move {
                let sigterm = tokio::signal::unix::SignalKind::hangup();
                #[allow(clippy::unwrap_used)]
                tokio::signal::unix::signal(sigterm).unwrap().recv().await
            } => {
                // Ignore
            }
            Some(()) = async move {
                let sigterm = tokio::signal::unix::SignalKind::user_defined1();
                #[allow(clippy::unwrap_used)]
                tokio::signal::unix::signal(sigterm).unwrap().recv().await
            } => {
                // Ignore
            }
            Some(()) = async move {
                let sigterm = tokio::signal::unix::SignalKind::user_defined2();
                #[allow(clippy::unwrap_used)]
                tokio::signal::unix::signal(sigterm).unwrap().recv().await
            } => {
                // Ignore
            }
        }
    }
    info!("Signal received, sending down signal to tasks");
    // Send a broadcast that we are done.
    if let Err(e) = broadcast_tx.send(true) {
        error!("Unable to shutdown workers {:?}", e);
    }

    // Wait for tasks to join.
    let _ = acceptor.await;
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let opt = Opt::parse();

    let level = if opt.debug {
        LevelFilter::TRACE
    } else {
        LevelFilter::INFO
    };

    tracing_forest::worker_task()
        .set_global(true)
        .map_sender(|sender| sender.or_stderr())
        .build_on(|subscriber| subscriber.with(level))
        .on(setup(&opt))
        .await;
}
