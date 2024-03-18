// use ldap_proxy::proxy::BasicLdapClient;

use ldap_proxy::Config;

#[test]
fn hello_world() {
    assert_eq!(2 + 2, 4);
}

#[test]
fn test_config_load() {
    assert!(toml::from_str::<Config>("").is_err());

    assert!(toml::from_str::<Config>(include_str!("test_config.toml")).is_ok());
    let config = toml::from_str::<Config>(include_str!("test_config.toml")).unwrap();

    assert_eq!(config.ldap_ca.to_str(), Some("/etc/ldap-proxy/ldap-ca.pem"));
}
