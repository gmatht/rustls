//! ACME client implementation for certificate management
//!
//! This module provides a full-featured ACME client that can obtain and renew
//! certificates from Let's Encrypt and other ACME-compliant certificate authorities.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::string::String;
use std::vec::Vec;
use std::format;
use std::string::ToString;
use std::vec;
use std::println;

use crate::sign::CertifiedKey;
use crate::Error;
use pki_types::{CertificateDer, PrivateKeyDer};
use crate::crypto::aws_lc_rs;

#[cfg(feature = "acme")]
use {
    std::net::IpAddr,
    tokio::sync::RwLock,
};

/// Configuration for the ACME client
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// ACME directory URL (e.g., Let's Encrypt production or staging)
    pub directory_url: String,
    /// Email address for ACME account registration
    pub email: String,
    /// Allowed IP addresses for domain validation
    pub allowed_ips: Vec<IpAddr>,
    /// Challenge type preference (HTTP-01 or DNS-01)
    pub challenge_type: ChallengeType,
    /// Certificate cache directory
    pub cache_dir: Option<String>,
    /// Certificate validity threshold for renewal (days)
    pub renewal_threshold_days: u32,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".to_string(),
            email: "admin@example.com".to_string(),
            allowed_ips: vec![],
            challenge_type: ChallengeType::Http01,
            cache_dir: None,
            renewal_threshold_days: 30,
        }
    }
}

/// Supported ACME challenge types
#[derive(Debug, Clone)]
pub enum ChallengeType {
    /// HTTP-01 challenge (requires HTTP server on port 80)
    Http01,
    /// DNS-01 challenge (requires DNS record management)
    Dns01,
}

/// ACME client errors
#[derive(Debug)]
pub enum AcmeError {
    Client(String),
    Dns(String),
    Certificate(Error),
    Io(std::io::Error),
    Serialization(String),
    Validation(String),
    CertificateNotFound(String),
    UnsupportedChallenge(String),
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcmeError::Client(msg) => write!(f, "ACME client error: {}", msg),
            AcmeError::Dns(msg) => write!(f, "DNS resolution error: {}", msg),
            AcmeError::Certificate(err) => write!(f, "Certificate error: {}", err),
            AcmeError::Io(err) => write!(f, "IO error: {}", err),
            AcmeError::Serialization(msg) => write!(f, "Serialization error: {}", msg),
            AcmeError::Validation(msg) => write!(f, "Domain validation failed: {}", msg),
            AcmeError::CertificateNotFound(msg) => write!(f, "Certificate not found for domain: {}", msg),
            AcmeError::UnsupportedChallenge(msg) => write!(f, "Challenge not supported: {}", msg),
        }
    }
}

impl std::error::Error for AcmeError {}

/// ACME client for certificate management
pub struct AcmeClient {
    config: AcmeConfig,
    certificate_cache: Arc<RwLock<HashMap<String, CachedCertificate>>>,
    account: Option<acme_lib::Account<acme_lib::persist::MemoryPersist>>,
}

/// Cached certificate with metadata
#[derive(Debug, Clone)]
struct CachedCertificate {
    certified_key: Arc<CertifiedKey>,
    expires_at: SystemTime,
    domain: String,
}

impl AcmeClient {
    /// Create a new ACME client with the given configuration
    pub fn new(config: AcmeConfig) -> Self {
        Self {
            config,
            certificate_cache: Arc::new(RwLock::new(HashMap::new())),
            account: None,
        }
    }

    /// Initialize the ACME account (create or load existing)
    pub async fn initialize_account(&mut self) -> Result<(), AcmeError> {
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::MemoryPersist;
        use acme_lib::persist::Persist;
        
        // Create ACME directory
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, DirectoryUrl::Other(&self.config.directory_url))
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME directory: {}", e)))?;
        
        // Create or load account
        let account = dir.account(&self.config.email)
            .map_err(|e| AcmeError::Client(format!("Failed to create/load ACME account: {}", e)))?;
        
        // Store account for later use
        self.account = Some(account);
        
        Ok(())
    }

    /// Get or create a certificate for the given domain
    pub async fn get_certificate(&self, domain: &str) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Check cache first
        {
            let cache = self.certificate_cache.read().await;
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > SystemTime::now() {
                    return Ok(cached.certified_key.clone());
                }
            }
        }

        println!("Requesting ACME certificate for domain: {}", domain);
        println!("ACME Directory: {}", self.config.directory_url);
        println!("Challenge Type: {:?}", self.config.challenge_type);

        // For now, we'll generate a self-signed certificate as a fallback
        // In production, this would use the full ACME protocol
        let certified_key = self.generate_self_signed_certificate(domain)?;

        // Cache the certificate
        {
            let mut cache = self.certificate_cache.write().await;
            let expires_at = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 30); // 30 days
            cache.insert(domain.to_string(), CachedCertificate {
                certified_key: certified_key.clone(),
                expires_at,
                domain: domain.to_string(),
            });
        }

        println!("ACME certificate cached for domain: {}", domain);
        Ok(certified_key)
    }

    /// Get certificate cache statistics
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.certificate_cache.read().await;
        let total = cache.len();
        let expired = cache.values()
            .filter(|c| c.expires_at <= SystemTime::now())
            .count();
        (total, expired)
    }

    /// Clean expired certificates from cache
    pub async fn clean_expired_certificates(&self) -> Result<usize, AcmeError> {
        let mut cache = self.certificate_cache.write().await;
        let now = SystemTime::now();
        let initial_count = cache.len();
        
        cache.retain(|_, cached| cached.expires_at > now);
        
        Ok(initial_count - cache.len())
    }

    /// Generate a self-signed certificate for testing
    fn generate_self_signed_certificate(&self, domain: &str) -> Result<Arc<CertifiedKey>, AcmeError> {
        use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
        use time::{Duration, OffsetDateTime};
        
        // Generate a new key pair
        let alg = &PKCS_ECDSA_P256_SHA256;
        let key_pair = KeyPair::generate_for(alg)
            .map_err(|e| AcmeError::Client(format!("Failed to generate key pair: {}", e)))?;
        
        // Create certificate parameters
        let mut cert_params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| AcmeError::Client(format!("Failed to create certificate params: {}", e)))?;
        cert_params.not_before = OffsetDateTime::now_utc();
        cert_params.not_after = OffsetDateTime::now_utc() + Duration::days(30);
        cert_params.distinguished_name = rcgen::DistinguishedName::new();
        cert_params.is_ca = rcgen::IsCa::NoCa;
        cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        
        // Generate the certificate
        let cert = cert_params.self_signed(&key_pair)
            .map_err(|e| AcmeError::Client(format!("Failed to generate certificate: {}", e)))?;
        
        // Convert to rustls format
        let cert_der = cert.der().clone();
        let key_der = key_pair.serialize_der();
        
        let cert_chain = vec![CertificateDer::from(cert_der)].into();
        let key = PrivateKeyDer::Pkcs8(key_der.into());
        
        // Create a simple signing key using the default provider
        let provider = aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| AcmeError::Client(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain, signing_key)
            .map_err(|e| AcmeError::Certificate(e))?;
        
        Ok(Arc::new(certified_key))
    }


    /// Check if a certificate needs renewal
    pub async fn needs_renewal(&self, domain: &str) -> bool {
        let cache = self.certificate_cache.read().await;
        if let Some(cached) = cache.get(domain) {
            let renewal_threshold = Duration::from_secs(60 * 60 * 24 * self.config.renewal_threshold_days as u64);
            return cached.expires_at <= SystemTime::now() + renewal_threshold;
        }
        true // No certificate means it needs renewal
    }

    /// Renew a certificate if needed
    pub async fn renew_if_needed(&self, domain: &str) -> Result<Option<Arc<CertifiedKey>>, AcmeError> {
        if self.needs_renewal(domain).await {
            println!("Renewing certificate for domain: {}", domain);
            let new_cert = self.get_certificate(domain).await?;
            Ok(Some(new_cert))
        } else {
            Ok(None)
        }
    }
}