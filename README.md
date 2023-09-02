# Ldap Proxy

A fast, simple, in-memory caching proxy for ldap that allows limiting of dn's and their searches.

```
tls_chain =
tls_key =

ldap_ca =
ldap_url =

[anonymous]

[cn=Administrator]
allow_filter = [
    "(objectClass=*)"
]


```
