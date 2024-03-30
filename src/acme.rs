use crate::ConfAcme;
use clap::Parser;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use std::{io, time::Duration};
use thiserror::Error;
use tokio::time::sleep;
use tracing;
use tracing::{error, info};

use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio_rustls_acme::{caches::DirCache, AcmeConfig};

use tokio_stream::wrappers::TcpListenerStream;

pub async fn request_cert(conf: ConfAcme) {
    //simple_logger::init_with_level(log::Level::Info).unwrap();

    let tcp_listener = tokio::net::TcpListener::bind("[::]:443").await.unwrap();
    let tcp_incoming = tokio_stream::wrappers::TcpListenerStream::new(tcp_listener);

    let mut tls_incoming = AcmeConfig::new(["c-nb"])
        .directory("https://localhost:14000/dir")
        .contact_push("mailto:admin@example.com")
        .cache(DirCache::new("./rustls_acme_cache"))
        .incoming(tcp_incoming, Vec::new());

    while let Some(tls) = tls_incoming.next().await {
        let mut tls = tls.unwrap();
        tokio::spawn(async move {
            tls.write_all(HELLO).await.unwrap();
            tls.shutdown().await.unwrap();
        });
    }
}

const HELLO: &'static [u8] = br#"HTTP/1.1 200 OK
Content-Length: 11
Content-Type: text/plain; charset=utf-8

Hello Tls!"#;
