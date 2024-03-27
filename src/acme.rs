use crate::ConfAcme;
use std::{io, time::Duration};

use clap::Parser;
use rcgen::{Certificate, CertificateParams, DistinguishedName};
use tokio::time::sleep;
use tracing::{error, info};

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};

pub fn request_cert(conf: ConfAcme) {
    // Use DirectoryUrl::LetsEncrypStaging for dev/testing.
    // Ok(())
}
