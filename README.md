# Ldap Proxy

A fast, simple, in-memory caching proxy for ldap that allows limiting of dn's and their searches.

```
bind = "127.0.0.1:3636"
tls_chain = "/tmp/chain.pem"
tls_key = "/tmp/key.pem"

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


## TODO:

* Allow control of cache size management.
* Allow configuration of cache entry timeouts.
* Allow configuration of client timeouts.
* Improve handling of client timeout from server.

