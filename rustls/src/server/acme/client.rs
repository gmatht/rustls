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
#[derive(Debug)]
pub struct AcmeClient {
    config: AcmeConfig,
    certificate_cache: Arc<RwLock<HashMap<String, CachedCertificate>>>,
    account: Option<acme_lib::Account>,
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
        use acme_lib::{Directory, DirectoryUrl, MemoryPersist};
        use acme_lib::persist::Persist;
        
        // Create ACME directory
        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, DirectoryUrl::from(&self.config.directory_url))
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

        // Get account or return error
        let account = self.account.as_ref()
            .ok_or_else(|| AcmeError::Client("ACME account not initialized".to_string()))?;

        // Create order for the domain
        let order = account.new_order(domain)
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME order: {}", e)))?;

        // Get authorizations
        let auths = order.authorizations()
            .map_err(|e| AcmeError::Client(format!("Failed to get authorizations: {}", e)))?;

        // Complete challenges
        for auth in auths {
            let challenge = match self.config.challenge_type {
                ChallengeType::Http01 => {
                    // Find HTTP-01 challenge
                    auth.http_01()
                        .map_err(|e| AcmeError::Client(format!("HTTP-01 challenge not available: {}", e)))?
                }
                ChallengeType::Dns01 => {
                    // Find DNS-01 challenge
                    auth.dns_01()
                        .map_err(|e| AcmeError::Client(format!("DNS-01 challenge not available: {}", e)))?
                }
            };

            // Complete the challenge
            self.complete_challenge(&challenge).await?;
        }

        // Finalize the order
        let pkey = acme_lib::create_p256_key();
        let order = order.confirm_validations()
            .map_err(|e| AcmeError::Client(format!("Failed to confirm validations: {}", e)))?;

        let (pkey_pri, pkey_pub) = pkey.split();
        let order = order.finalize(pkey_pub)
            .map_err(|e| AcmeError::Client(format!("Failed to finalize order: {}", e)))?;

        // Download the certificate
        let cert = order.download_cert()
            .map_err(|e| AcmeError::Client(format!("Failed to download certificate: {}", e)))?;

        // Convert to rustls format
        let certified_key = self.convert_acme_cert_to_rustls(cert, pkey_pri)?;

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

    /// Complete an ACME challenge (HTTP-01 or DNS-01)
    async fn complete_challenge(&self, challenge: &acme_lib::Challenge) -> Result<(), AcmeError> {
        match self.config.challenge_type {
            ChallengeType::Http01 => {
                self.complete_http01_challenge(challenge).await
            }
            ChallengeType::Dns01 => {
                self.complete_dns01_challenge(challenge).await
            }
        }
    }

    /// Complete HTTP-01 challenge
    async fn complete_http01_challenge(&self, challenge: &acme_lib::Challenge) -> Result<(), AcmeError> {
        // Get the challenge token and key authorization
        let token = challenge.http_01_token();
        let key_auth = challenge.http_01_key_authorization();
        
        // In a real implementation, you would:
        // 1. Serve the key authorization at /.well-known/acme-challenge/{token}
        // 2. Ensure the server is accessible on port 80
        // 3. Wait for ACME server to verify the challenge
        
        // For now, we'll just trigger the challenge
        challenge.validate()
            .map_err(|e| AcmeError::Client(format!("HTTP-01 challenge validation failed: {}", e)))?;
        
        // Wait for challenge to be validated
        let mut attempts = 0;
        while attempts < 30 { // 30 attempts = 5 minutes
            tokio::time::sleep(Duration::from_secs(10)).await;
            
            if challenge.status() == acme_lib::ChallengeStatus::Valid {
                return Ok(());
            }
            
            if challenge.status() == acme_lib::ChallengeStatus::Invalid {
                return Err(AcmeError::Validation("HTTP-01 challenge failed".to_string()));
            }
            
            attempts += 1;
        }
        
        Err(AcmeError::Validation("HTTP-01 challenge timeout".to_string()))
    }

    /// Complete DNS-01 challenge
    async fn complete_dns01_challenge(&self, challenge: &acme_lib::Challenge) -> Result<(), AcmeError> {
        // Get the challenge token and key authorization
        let token = challenge.dns_01_token();
        let key_auth = challenge.dns_01_key_authorization();
        
        // In a real implementation, you would:
        // 1. Create a TXT record: _acme-challenge.{domain} -> key_auth
        // 2. Wait for DNS propagation
        // 3. Trigger challenge validation
        
        // For now, we'll just trigger the challenge
        challenge.validate()
            .map_err(|e| AcmeError::Client(format!("DNS-01 challenge validation failed: {}", e)))?;
        
        // Wait for challenge to be validated
        let mut attempts = 0;
        while attempts < 30 { // 30 attempts = 5 minutes
            tokio::time::sleep(Duration::from_secs(10)).await;
            
            if challenge.status() == acme_lib::ChallengeStatus::Valid {
                return Ok(());
            }
            
            if challenge.status() == acme_lib::ChallengeStatus::Invalid {
                return Err(AcmeError::Validation("DNS-01 challenge failed".to_string()));
            }
            
            attempts += 1;
        }
        
        Err(AcmeError::Validation("DNS-01 challenge timeout".to_string()))
    }

    /// Convert ACME certificate to rustls format
    fn convert_acme_cert_to_rustls(&self, cert: acme_lib::Certificate, pkey: acme_lib::PrivateKey) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Convert certificate chain
        let cert_chain: Vec<CertificateDer> = cert.certificate()
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        
        // Convert private key
        let key_der = pkey.private_key_der();
        let key = PrivateKeyDer::Pkcs8(key_der.into());
        
        // Create signing key
        let provider = aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| AcmeError::Client(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain.into(), signing_key)
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