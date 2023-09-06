# Ldap Proxy

A fast, simple, in-memory caching proxy for ldap that allows limiting of dn's and their searches.

```
# /data/config.toml for containers.
# /etc/ldap-proxy/config.toml for packaged versions.

bind = "127.0.0.1:3636"
tls_chain = "/tmp/chain.pem"
tls_key = "/tmp/key.pem"

# Number of bytes of entries to store in the cache
# cache_bytes = 137438953472
# Seconds that entries remain valid in cache
# cache_entry_timeout = 1800

# The max ber size of requests from clients
# max_incoming_ber_size = 8388608
# The max ber size of responses from the upstream ldap server
# max_proxy_ber_size = 8388608

ldap_ca = "/tmp/ldap-ca.pem"
ldap_url = "ldaps://idm.example.com"

# "" is the anonymous dn
[""]
allowed_queries = [
    ["", "base", "(objectclass=*)"],
    ["o=example", "subtree", "(objectclass=*)"],
]

[cn=Administrator]
# If you don't specify allowed queries, all queries are granted

[cn=user]
allowed_queries = [
    ["", "base", "(objectclass=*)"],
]

```

## Where do I get it?

* OpenSUSE: `zypper in ldap-proxy`
* docker: `docker pull firstyear/ldap-proxy:latest`

## TODO:

* Allow configuration of client timeouts.
* Improve handling of client timeout from server.

