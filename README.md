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

# By default only DNs listed in the bind-maps may bind. All other
# DNs that do not have a bind-map entry may not proceed. Setting
# this allows all DNs to bind through the server. When this is
# true, if the DN has a bind-map it will filter the queries of that
# DN. If the DN does not have a bind map, it allows all queries.
#
# Another way to think of this is that setting this to "false"
# makes this an ldap firewall. Setting this to "true" turns this
# into a search-caching proxy.
#
# allow_all_bind_dns = false

ldap_ca = "/tmp/ldap-ca.pem"
ldap_url = "ldaps://idm.example.com"


# Bind Maps
#
# This allows you to configure which DNs can bind, and what search
# queries they may perform.
#
# "" is the anonymous dn
[""]
allowed_queries = [
    ["", "base", "(objectclass=*)"],
    ["o=example", "subtree", "(objectclass=*)"],
]

["cn=Administrator"]
# If you don't specify allowed queries, all queries are granted

["cn=user"]
allowed_queries = [
    ["", "base", "(objectclass=*)"],
]

```

## Where do I get it?

* OpenSUSE: `zypper in ldap-proxy`
* docker: `docker pull firstyear/ldap-proxy:latest`

## FAQ

### Why can't ldap-proxy running under systemd read my certificates?

Because we use systemd dynamic users. This means that ldap-proxy is always isolated in a sandboxed
user, and that user can dynamically change it's uid/gid.

To resolve this, you need to add ldap-proxy to have a supplemental group that can read your certs.

```
# systemctl edit ldap-proxy
[Service]
SupplementaryGroups=certbot
```

Then restart ldap-proxy. Also be sure to check that the group has proper execute bits along the
directory paths and that the certs are readable to the group!


