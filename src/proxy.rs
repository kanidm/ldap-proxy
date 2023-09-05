use futures_util::sink::SinkExt;
use futures_util::stream::StreamExt;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};
use tracing::{debug, error, info, span, trace, warn, Level};

use openssl::ssl::{Ssl, SslConnector};
use std::hash::Hash;
use std::pin::Pin;
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use ldap3_proto::proto::*;
use ldap3_proto::LdapCodec;

use std::time::Instant;

use crate::{AppState, DnConfig};

type CR = ReadHalf<SslStream<TcpStream>>;
type CW = WriteHalf<SslStream<TcpStream>>;

#[derive(Debug, Clone, Hash, PartialOrd, Ord, Eq, PartialEq)]
pub struct SearchCacheKey {
    bind_dn: String,
    search: LdapSearchRequest,
    ctrl: Vec<LdapControl>,
}

#[derive(Debug, Clone)]
pub struct CachedValue {
    valid_until: Instant,
    entries: Vec<(LdapSearchResultEntry, Vec<LdapControl>)>,
    result: LdapResult,
    ctrl: Vec<LdapControl>,
}

impl CachedValue {
    fn size(&self) -> usize {
        std::mem::size_of::<Self>() + self.entries.iter().map(|(e, _)| e.size()).sum::<usize>()
    }
}

enum ClientState {
    Unbound,
    Authenticated {
        dn: String,
        config: DnConfig,
        client: BasicLdapClient,
    },
}

fn bind_operror(msgid: i32, msg: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: LdapResult {
                code: LdapResultCode::OperationsError,
                matcheddn: "".to_string(),
                message: msg.to_string(),
                referral: vec![],
            },
            saslcreds: None,
        }),
        ctrl: vec![],
    }
}

pub(crate) async fn client_process<W: AsyncWrite + Unpin, R: AsyncRead + Unpin>(
    mut r: FramedRead<R, LdapCodec>,
    mut w: FramedWrite<W, LdapCodec>,
    client_address: SocketAddr,
    app_state: Arc<AppState>,
) {
    info!("Accept from {}", client_address);

    // We always start unbound.
    let mut state = ClientState::Unbound;

    // Start to wait for incomming packets
    while let Some(Ok(protomsg)) = r.next().await {
        let next_state = match (&mut state, protomsg) {
            // Doesn't matter what state we are in, any bind will trigger this process.
            (
                _,
                LdapMsg {
                    msgid,
                    op: LdapOp::BindRequest(lbr),
                    ctrl,
                },
            ) => {
                let span = span!(Level::INFO, "bind");
                let _enter = span.enter();

                trace!(?lbr);
                // Is the requested bind dn valid per our map?
                let config = match app_state.binddn_map.get(&lbr.dn) {
                    Some(dnconfig) => {
                        // They have a config! They can proceed.
                        dnconfig.clone()
                    }
                    None => {
                        // No config found, sad trombone.
                        let resp_msg = bind_operror(msgid, "unable to bind");
                        if w.send(resp_msg).await.is_err() {
                            error!("Unable to send response");
                            break;
                        }
                        continue;
                    }
                };

                // Okay, we have a dnconfig, so they are allowed to proceed. Lets
                // now setup the client for their session, and anything else we
                // need to configure.

                let dn = lbr.dn.clone();

                // We need the client to connect *and* bind to proceed here!
                let mut client = match BasicLdapClient::build(
                    &app_state.addrs,
                    &app_state.tls_params,
                    app_state.max_proxy_ber_size,
                )
                .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        error!(?e, "A client build error has occured.");
                        let resp_msg = bind_operror(msgid, "unable to bind");
                        if w.send(resp_msg).await.is_err() {
                            error!("Unable to send response");
                        }
                        // Always bail.
                        break;
                    }
                };

                let valid = match client.bind(lbr, ctrl).await {
                    Ok((bind_resp, ctrl)) => {
                        // Almost there, lets check the bind result.
                        let valid = bind_resp.res.code == LdapResultCode::Success;

                        let resp_msg = LdapMsg {
                            msgid,
                            op: LdapOp::BindResponse(bind_resp),
                            ctrl,
                        };
                        if w.send(resp_msg).await.is_err() {
                            error!("Unable to send response");
                            break;
                        }
                        valid
                    }
                    Err(e) => {
                        error!(?e, "A client bind error has occured");
                        let resp_msg = bind_operror(msgid, "unable to bind");
                        if w.send(resp_msg).await.is_err() {
                            error!("Unable to send response");
                        }
                        // Always bail.
                        break;
                    }
                };

                if valid {
                    info!("Successful bind for {}", dn);
                    Some(ClientState::Authenticated { dn, config, client })
                } else {
                    None
                }
            }
            // Unbinds are always actioned.
            (
                _,
                LdapMsg {
                    msgid: _,
                    op: LdapOp::UnbindRequest,
                    ctrl: _,
                },
            ) => {
                trace!("unbind");
                break;
            }

            // Authenticated message handler.
            //  - Search
            (
                ClientState::Authenticated {
                    dn,
                    config,
                    ref mut client,
                },
                LdapMsg {
                    msgid,
                    op: LdapOp::SearchRequest(sr),
                    ctrl,
                },
            ) => {
                let span = span!(Level::INFO, "search");
                let _enter = span.enter();

                // Pre check if the search is allowed for this dn / scope / filter
                if config.allowed_queries.is_empty() {
                    // All queries are allowed.
                    debug!("All queries are allowed");
                } else {
                    // Let's check the query details.
                    let allow_key = (sr.base.clone(), sr.scope.clone(), sr.filter.clone());

                    if config.allowed_queries.contains(&allow_key) {
                        // Good to proceed.
                        debug!("Query is granted");
                    } else {
                        warn!(?allow_key, "Requested query is not allowed for {}", dn);
                        // If not, send an empty result.
                        if w.send(LdapMsg {
                            msgid,
                            op: LdapOp::SearchResultDone(LdapResult {
                                code: LdapResultCode::Success,
                                matcheddn: "".to_string(),
                                message: "".to_string(),
                                referral: vec![],
                            }),
                            ctrl,
                        })
                        .await
                        .is_err()
                        {
                            error!("Unable to send response");
                        }
                        // Always bail.
                        break;
                    }
                };

                // This is done like this to facilitate a cache mechanism in future.
                //
                // Cache will need to key on:
                //    bind_dn
                //    base
                //    scope
                //    deref aliases
                //    types only
                //    filter
                //    attrs
                //   search controls
                //
                // Which is a lot, but it's everything that controls to results to
                // ensure we don't introduce corruption.

                let now = Instant::now();

                // get the read txn.
                let mut cache_read_txn = app_state.cache.read();

                let cache_key = SearchCacheKey {
                    bind_dn: dn.clone(),
                    search: sr.clone(),
                    ctrl: ctrl.clone(),
                };
                debug!(?cache_key);

                let maybe_results = cache_read_txn.get(&cache_key).and_then(|cache_value| {
                    if cache_value.valid_until > now {
                        Some(cache_value.clone())
                    } else {
                        debug!("Cache item expired");
                        None
                    }
                });

                let was_cache_miss = maybe_results.is_none();

                debug!("cache hit {}", !was_cache_miss);

                let (entries, result, ctrl) = match maybe_results {
                    Some(CachedValue {
                        valid_until: _,
                        entries,
                        result,
                        ctrl,
                    }) => (entries, result, ctrl),
                    None => {
                        match client.search(sr, ctrl).await {
                            Ok(data) => data,
                            Err(e) => {
                                error!(?e, "A client search error has occured");
                                let resp_msg = bind_operror(msgid, "unable to search");
                                if w.send(resp_msg).await.is_err() {
                                    error!("Unable to send response");
                                }
                                // Always bail.
                                break;
                            }
                        }
                    }
                };

                // Update cache if needed.
                if was_cache_miss {
                    let cache_value = CachedValue {
                        valid_until: now + app_state.cache_entry_timeout,
                        entries: entries.clone(),
                        result: result.clone(),
                        ctrl: ctrl.clone(),
                    };
                    if let Some(cache_value_size) = NonZeroUsize::new(cache_value.size()) {
                        debug!("Adding entry of size {} to cache", cache_value_size);
                        cache_read_txn.insert_sized(cache_key, cache_value, cache_value_size);
                    } else {
                        error!("Invalid entry size, unable to add to cache");
                    }
                }

                for (entry, ctrl) in entries {
                    if w.send(LdapMsg {
                        msgid,
                        op: LdapOp::SearchResultEntry(entry),
                        ctrl,
                    })
                    .await
                    .is_err()
                    {
                        error!("Unable to send response");
                        break;
                    }
                }

                if w.send(LdapMsg {
                    msgid,
                    op: LdapOp::SearchResultDone(result),
                    ctrl,
                })
                .await
                .is_err()
                {
                    error!("Unable to send response");
                    break;
                }

                // Try and quiesce now.
                app_state.cache.try_quiesce();

                // No state change
                None
            }
            // Extended Requests - Generally has whoami.
            (
                ClientState::Authenticated {
                    dn,
                    config: _,
                    client: _,
                },
                LdapMsg {
                    msgid,
                    op: LdapOp::ExtendedRequest(ler),
                    ctrl: _,
                },
            ) => {
                let op = match ler.name.as_str() {
                    "1.3.6.1.4.1.4203.1.11.3" => LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: LdapResult {
                            code: LdapResultCode::Success,
                            matcheddn: "".to_string(),
                            message: "".to_string(),
                            referral: vec![],
                        },
                        name: None,
                        value: Some(Vec::from(dn.as_str())),
                    }),
                    _ => LdapOp::ExtendedResponse(LdapExtendedResponse {
                        res: LdapResult {
                            code: LdapResultCode::OperationsError,
                            matcheddn: "".to_string(),
                            message: "".to_string(),
                            referral: vec![],
                        },
                        name: None,
                        value: None,
                    }),
                };

                if w.send(LdapMsg {
                    msgid,
                    op,
                    ctrl: vec![],
                })
                .await
                .is_err()
                {
                    error!("Unable to send response");
                    break;
                }

                None
            }
            // Unknown message handler.
            (_, msg) => {
                debug!(?msg);
                // Return a disconnect.
                break;
            }
        };

        if let Some(next_state) = next_state {
            // Update the client state, dropping any former state.
            state = next_state;
        }
    }
    info!("Disconnect for {}", client_address);
}

#[derive(Debug, Clone)]
enum LdapError {
    TlsError,
    ConnectError,
    Transport,
    InvalidProtocolState,
}

struct BasicLdapClient {
    r: FramedRead<CR, LdapCodec>,
    w: FramedWrite<CW, LdapCodec>,
    msg_counter: i32,
}

impl BasicLdapClient {
    fn next_msgid(&mut self) -> i32 {
        self.msg_counter += 1;
        self.msg_counter
    }

    pub async fn build(
        addrs: &[SocketAddr],
        tls_connector: &SslConnector,
        max_ber_size: Option<usize>,
    ) -> Result<Self, LdapError> {
        let timeout = Duration::from_secs(5);

        let mut aiter = addrs.iter();

        let tcpstream = loop {
            if let Some(addr) = aiter.next() {
                let sleep = tokio::time::sleep(timeout);
                tokio::pin!(sleep);
                tokio::select! {
                    maybe_stream = TcpStream::connect(addr) => {
                        match maybe_stream {
                            Ok(t) => {
                                trace!(?addr, "connection established");
                                break t;
                            }
                            Err(e) => {
                                trace!(?addr, ?e, "error");
                                continue;
                            }
                        }
                    }
                    _ = &mut sleep => {
                        warn!(?addr, "timeout");
                        continue;
                    }
                }
            } else {
                return Err(LdapError::ConnectError);
            }
        };

        let mut tlsstream = Ssl::new(tls_connector.context())
            .and_then(|tls_obj| SslStream::new(tls_obj, tcpstream))
            .map_err(|e| {
                error!(?e, "openssl");
                LdapError::TlsError
            })?;

        SslStream::connect(Pin::new(&mut tlsstream))
            .await
            .map_err(|e| {
                error!(?e, "openssl");
                LdapError::TlsError
            })?;

        let (r, w) = tokio::io::split(tlsstream);

        let w = FramedWrite::new(w, LdapCodec::new(max_ber_size));
        let r = FramedRead::new(r, LdapCodec::new(max_ber_size));

        info!("Connected to remote ldap server");
        Ok(BasicLdapClient {
            r,
            w,
            msg_counter: 0,
        })
    }

    pub async fn bind(
        &mut self,
        lbr: LdapBindRequest,
        ctrl: Vec<LdapControl>,
    ) -> Result<(LdapBindResponse, Vec<LdapControl>), LdapError> {
        let ck_msgid = self.next_msgid();

        let msg = LdapMsg {
            msgid: ck_msgid,
            op: LdapOp::BindRequest(lbr),
            ctrl,
        };

        self.w.send(msg).await.map_err(|e| {
            error!(?e, "unable to transmit to ldap server");
            LdapError::Transport
        })?;

        match self.r.next().await {
            Some(Ok(LdapMsg {
                msgid,
                op: LdapOp::BindResponse(bind_resp),
                ctrl,
            })) => {
                if msgid == ck_msgid {
                    Ok((bind_resp, ctrl))
                } else {
                    error!("invalid msgid, sequence error.");
                    Err(LdapError::InvalidProtocolState)
                }
            }
            Some(Ok(msg)) => {
                trace!(?msg);
                Err(LdapError::InvalidProtocolState)
            }
            Some(Err(e)) => {
                error!(?e, "unable to receive from ldap server");
                Err(LdapError::Transport)
            }
            None => {
                error!("connection closed");
                Err(LdapError::Transport)
            }
        }
    }

    pub async fn search(
        &mut self,
        sr: LdapSearchRequest,
        ctrl: Vec<LdapControl>,
    ) -> Result<
        (
            Vec<(LdapSearchResultEntry, Vec<LdapControl>)>,
            LdapResult,
            Vec<LdapControl>,
        ),
        LdapError,
    > {
        let ck_msgid = self.next_msgid();

        let msg = LdapMsg {
            msgid: ck_msgid,
            op: LdapOp::SearchRequest(sr),
            ctrl,
        };

        self.w.send(msg).await.map_err(|e| {
            error!(?e, "unable to transmit to ldap server");
            LdapError::Transport
        })?;

        let mut entries = Vec::new();
        loop {
            match self.r.next().await {
                // This terminates the iteration of entries.
                Some(Ok(LdapMsg {
                    msgid,
                    op: LdapOp::SearchResultDone(search_res),
                    ctrl,
                })) => {
                    if msgid == ck_msgid {
                        break Ok((entries, search_res, ctrl));
                    } else {
                        error!("invalid msgid, sequence error.");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                Some(Ok(LdapMsg {
                    msgid,
                    op: LdapOp::SearchResultEntry(search_entry),
                    ctrl,
                })) => {
                    if msgid == ck_msgid {
                        entries.push((search_entry, ctrl))
                    } else {
                        error!("invalid msgid, sequence error.");
                        break Err(LdapError::InvalidProtocolState);
                    }
                }
                Some(Ok(msg)) => {
                    trace!(?msg);
                    break Err(LdapError::InvalidProtocolState);
                }
                Some(Err(e)) => {
                    error!(?e, "unable to receive from ldap server");
                    break Err(LdapError::Transport);
                }
                None => {
                    error!("connection closed");
                    break Err(LdapError::Transport);
                }
            }
        }
    }
}
