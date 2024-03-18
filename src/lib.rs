use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use concread::arcache::ARCache;
use hashbrown::HashSet;
use ldap3_proto::{LdapFilter, LdapSearchScope};
use openssl::ssl::SslConnector;
use serde::Deserialize;
use url::Url;

pub mod proxy;

use crate::proxy::{CachedValue, SearchCacheKey};

const MEGABYTES: usize = 1048576;

pub struct AppState {
    pub tls_params: SslConnector,
    pub addrs: Vec<SocketAddr>,
    // Cache later here.
    pub binddn_map: BTreeMap<String, DnConfig>,
    pub cache: ARCache<SearchCacheKey, CachedValue>,
    pub cache_entry_timeout: Duration,
    pub max_incoming_ber_size: Option<usize>,
    pub max_proxy_ber_size: Option<usize>,
    pub allow_all_bind_dns: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnConfig {
    #[serde(default)]
    pub allowed_queries: HashSet<(String, LdapSearchScope, LdapFilter)>,
}

fn default_cache_bytes() -> usize {
    128 * MEGABYTES
}

fn default_cache_entry_timeout() -> u64 {
    1800
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub bind: SocketAddr,
    pub tls_key: PathBuf,
    pub tls_chain: PathBuf,

    #[serde(default = "default_cache_bytes")]
    pub cache_bytes: usize,
    #[serde(default = "default_cache_entry_timeout")]
    pub cache_entry_timeout: u64,

    pub ldap_ca: PathBuf,
    pub ldap_url: Url,

    pub max_incoming_ber_size: Option<usize>,
    pub max_proxy_ber_size: Option<usize>,

    #[serde(default)]
    pub allow_all_bind_dns: bool,

    #[serde(flatten)]
    pub binddn_map: BTreeMap<String, DnConfig>,
}
