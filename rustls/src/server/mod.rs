//! Server-side TLS implementation
//!
//! This module contains the server-side implementation of the TLS protocol,
//! including connection handling, certificate management, and ACME integration.

pub mod acme;
pub mod builder;
pub mod handy;
pub mod hs;
pub mod server_conn;
pub mod test;
pub mod tls12;
pub mod tls13;

// Re-export commonly used types
pub use server_conn::{
    Acceptor, Accepted, ClientHello, InvalidSniPolicy, ResolvesServerCert, ServerConfig,
    ServerConnection, ServerSessionMemory, WantsServerCert,
};

// Re-export ACME types when feature is enabled
#[cfg(feature = "acme")]
pub use acme::{
    AcmeClient, OnDemandCertResolver, DnsValidator,
    types::{AcmeConfig, AcmeError, ValidationResult},
};



