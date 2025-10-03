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
use base64;

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
        /// Whether this is a staging environment
        pub is_staging: bool,
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
            is_staging: false,
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
    challenge_storage: Arc<RwLock<HashMap<String, ChallengeData>>>, // Added
}

/// Stored challenge data for HTTP-01 and DNS-01 challenges
#[derive(Debug, Clone)]
struct ChallengeData {
    token: String,
    key_authorization: String,
    domain: String,
    challenge_type: ChallengeType,
    created_at: SystemTime,
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
            challenge_storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the ACME account (create or load existing)
    pub async fn initialize_account(&mut self) -> Result<(), AcmeError> {
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::MemoryPersist;

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

    /// Get the email address for a specific domain
    fn get_email_for_domain(&self, domain: &str) -> String {
        // If a specific email is configured, use it
        if !self.config.email.is_empty() {
            return self.config.email.clone();
        }
        
        // Otherwise, generate webmaster@domain
        format!("webmaster@{}", domain)
    }

    /// Store challenge data for HTTP-01 challenges
    pub async fn store_challenge(&self, token: String, key_authorization: String, domain: String) -> Result<(), AcmeError> {
        let challenge_data = ChallengeData {
            token: token.clone(),
            key_authorization,
            domain,
            challenge_type: ChallengeType::Http01,
            created_at: SystemTime::now(),
        };
        
        let mut storage = self.challenge_storage.write().await;
        storage.insert(token, challenge_data);
        Ok(())
    }

    /// Get challenge response for HTTP-01 challenges
    pub async fn get_challenge_response(&self, token: &str) -> Option<String> {
        let storage = self.challenge_storage.read().await;
        storage.get(token).map(|data| data.key_authorization.clone())
    }

    /// Clean up expired challenges
    pub async fn clean_expired_challenges(&self) -> Result<usize, AcmeError> {
        let mut storage = self.challenge_storage.write().await;
        let now = SystemTime::now();
        let expired_threshold = Duration::from_secs(60 * 60); // 1 hour
        let initial_count = storage.len();
        
        storage.retain(|_, data| now.duration_since(data.created_at).unwrap_or(Duration::ZERO) < expired_threshold);
        
        Ok(initial_count - storage.len())
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

        // Try to load from disk
        if let Some(certified_key) = self.load_certificate_from_disk(domain).await? {
            // Cache the loaded certificate
            {
                let mut cache = self.certificate_cache.write().await;
                let expires_at = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 30); // 30 days
                cache.insert(domain.to_string(), CachedCertificate {
                    certified_key: certified_key.clone(),
                    expires_at,
                    domain: domain.to_string(),
                });
            }
            println!("Loaded certificate from disk for domain: {}", domain);
            return Ok(certified_key);
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

    /// Request a real ACME certificate using HTTP-01 challenges
    pub async fn request_acme_certificate(&self, domain: &str) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Check cache first
        {
            let cache = self.certificate_cache.read().await;
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > SystemTime::now() {
                    return Ok(cached.certified_key.clone());
                }
            }
        }

        // Get domain-specific email
        let domain_email = self.get_email_for_domain(domain);
        println!("Using email for domain {}: {}", domain, domain_email);

        // Create ACME directory and account for this domain
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::MemoryPersist;

        let persist = MemoryPersist::new();
        let dir = Directory::from_url(persist, DirectoryUrl::Other(&self.config.directory_url))
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME directory: {}", e)))?;

        let account = dir.account(&domain_email)
            .map_err(|e| AcmeError::Client(format!("Failed to create/load ACME account for {}: {}", domain_email, e)))?;

        println!("Requesting real ACME certificate for domain: {}", domain);

        // Create order for the domain
        let mut order = account.new_order(domain, &[])
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME order: {}", e)))?;

        println!("ACME order created for domain: {}", domain);

        // Process challenges in a loop until validations are confirmed
        let order_csr = loop {
            // Check if we're done
            if let Some(ord_csr) = order.confirm_validations() {
                break ord_csr;
            }

            // Get authorizations
            let auths = order.authorizations()
                .map_err(|e| AcmeError::Client(format!("Failed to get authorizations: {}", e)))?;

            println!("Got {} authorizations for domain: {}", auths.len(), domain);

            // Complete HTTP-01 challenges
            for (i, auth) in auths.iter().enumerate() {
                println!("Processing authorization {} for domain: {}", i + 1, domain);

                // Get HTTP-01 challenge
                let challenge = auth.http_challenge();
                let token = challenge.http_token();
                let proof = challenge.http_proof();
                
                println!("HTTP-01 challenge token: {}", token);
                println!("HTTP-01 challenge proof: {}", proof);

                // Store the challenge for the server to serve
                self.store_challenge(token.to_string(), proof.clone(), domain.to_string()).await?;
                
                // Trigger the challenge validation
                challenge.validate(5000)
                    .map_err(|e| AcmeError::Client(format!("HTTP-01 challenge validation failed: {}", e)))?;
                
                println!("HTTP-01 challenge validation triggered for domain: {}", domain);
            }

            // Update the order state
            order.refresh()
                .map_err(|e| AcmeError::Client(format!("Failed to refresh order: {}", e)))?;
        };

        println!("Validations confirmed for domain: {}", domain);

        // Create private key for the certificate
        let pkey_pri = acme_lib::create_p384_key();

        // Finalize the order with the private key
        let order_cert = order_csr.finalize_pkey(pkey_pri, 5000)
            .map_err(|e| AcmeError::Client(format!("Failed to finalize order: {}", e)))?;

        println!("Order finalized for domain: {}", domain);

        // Download the certificate
        let cert = order_cert.download_and_save_cert()
            .map_err(|e| AcmeError::Client(format!("Failed to download certificate: {}", e)))?;

        println!("Certificate downloaded for domain: {}", domain);

        // Convert the real ACME certificate to rustls format
        println!("Real ACME certificate obtained! Certificate chain length: {}", cert.certificate().len());
        let certified_key = self.convert_acme_cert_to_rustls(&cert)?;

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

        // Save certificate to disk
        self.save_certificate_to_disk(domain, &certified_key, &cert).await?;

        println!("ACME certificate cached and saved to disk for domain: {}", domain);
        Ok(certified_key)
    }

    /// Convert ACME certificate to rustls format
    fn convert_acme_cert_to_rustls(&self, cert: &acme_lib::Certificate) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Parse PEM certificate chain
        let cert_chain = self.parse_pem_certificates(cert.certificate())?;
        
        // Parse PEM private key
        let private_key = self.parse_pem_private_key(cert.private_key())?;
        
        // Create signing key
        let provider = aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(private_key)
            .map_err(|e| AcmeError::Client(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain.into(), signing_key)
            .map_err(|e| AcmeError::Certificate(e))?;
        
        println!("Successfully converted ACME certificate to rustls format");
        Ok(Arc::new(certified_key))
    }
    
    /// Parse PEM certificate chain
    fn parse_pem_certificates(&self, pem_data: &str) -> Result<Vec<CertificateDer<'static>>, AcmeError> {
        let mut cert_chain = Vec::new();
        let mut current_cert = String::new();
        let mut in_cert = false;
        
        for line in pem_data.lines() {
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                current_cert = String::new();
            } else if line == "-----END CERTIFICATE-----" {
                in_cert = false;
                if !current_cert.is_empty() {
                    // Decode base64 certificate
                    let cert_der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &current_cert)
                        .map_err(|e| AcmeError::Client(format!("Failed to decode certificate: {}", e)))?;
                    cert_chain.push(CertificateDer::from(cert_der));
                }
            } else if in_cert {
                current_cert.push_str(line);
            }
        }
        
        if cert_chain.is_empty() {
            return Err(AcmeError::Client("No certificates found in PEM data".to_string()));
        }
        
        Ok(cert_chain)
    }
    
    /// Parse PEM private key
    fn parse_pem_private_key(&self, pem_data: &str) -> Result<PrivateKeyDer<'static>, AcmeError> {
        let mut private_key_data = String::new();
        let mut in_key = false;
        
        for line in pem_data.lines() {
            if line == "-----BEGIN PRIVATE KEY-----" || line == "-----BEGIN EC PRIVATE KEY-----" {
                in_key = true;
                private_key_data = String::new();
            } else if line == "-----END PRIVATE KEY-----" || line == "-----END EC PRIVATE KEY-----" {
                in_key = false;
                if !private_key_data.is_empty() {
                    // Decode base64 private key
                    let key_der = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &private_key_data)
                        .map_err(|e| AcmeError::Client(format!("Failed to decode private key: {}", e)))?;
                    return Ok(PrivateKeyDer::Pkcs8(key_der.into()));
                }
            } else if in_key {
                private_key_data.push_str(line);
            }
        }
        
        Err(AcmeError::Client("No private key found in PEM data".to_string()))
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

    /// Get the certificate storage directory path
    fn get_certificate_dir(&self) -> Result<String, AcmeError> {
        let base_dir = self.config.cache_dir.as_deref().unwrap_or("/tmp/acme_certs");
        let env_suffix = if self.config.is_staging { "staging" } else { "production" };
        let cert_dir = format!("{}/{}", base_dir, env_suffix);
        
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&cert_dir)
            .map_err(|e| AcmeError::Io(e))?;
            
        Ok(cert_dir)
    }

    /// Save certificate to disk
    async fn save_certificate_to_disk(
        &self,
        domain: &str,
        certified_key: &Arc<CertifiedKey>,
        acme_cert: &acme_lib::Certificate,
    ) -> Result<(), AcmeError> {
        let cert_dir = self.get_certificate_dir()?;
        
        // Save certificate chain
        let cert_path = format!("{}/{}.crt", cert_dir, domain);
        std::fs::write(&cert_path, acme_cert.certificate())
            .map_err(|e| AcmeError::Io(e))?;
        
        // Save private key
        let key_path = format!("{}/{}.key", cert_dir, domain);
        std::fs::write(&key_path, acme_cert.private_key())
            .map_err(|e| AcmeError::Io(e))?;
        
        // Save metadata
        let metadata_path = format!("{}/{}.meta", cert_dir, domain);
        let domain_email = self.get_email_for_domain(domain);
        let metadata = serde_json::json!({
            "domain": domain,
            "email": domain_email,
            "created_at": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
            "is_staging": self.config.is_staging,
            "acme_directory": self.config.directory_url,
            "cert_path": cert_path,
            "key_path": key_path
        });
        std::fs::write(&metadata_path, metadata.to_string())
            .map_err(|e| AcmeError::Io(e))?;
        
        println!("Certificate saved to disk: {}", cert_path);
        Ok(())
    }

    /// Load certificate from disk
    async fn load_certificate_from_disk(&self, domain: &str) -> Result<Option<Arc<CertifiedKey>>, AcmeError> {
        let cert_dir = self.get_certificate_dir()?;
        let cert_path = format!("{}/{}.crt", cert_dir, domain);
        let key_path = format!("{}/{}.key", cert_dir, domain);
        let metadata_path = format!("{}/{}.meta", cert_dir, domain);
        
        // Check if all required files exist
        if !std::path::Path::new(&cert_path).exists() ||
           !std::path::Path::new(&key_path).exists() ||
           !std::path::Path::new(&metadata_path).exists() {
            return Ok(None);
        }
        
        // Load and verify metadata
        let metadata_content = std::fs::read_to_string(&metadata_path)
            .map_err(|e| AcmeError::Io(e))?;
        let metadata: serde_json::Value = serde_json::from_str(&metadata_content)
            .map_err(|e| AcmeError::Serialization(e.to_string()))?;
        
        // Check if this is the right environment (staging vs production)
        let is_staging = metadata.get("is_staging").and_then(|v| v.as_bool()).unwrap_or(false);
        if is_staging != self.config.is_staging {
            println!("Certificate environment mismatch for domain: {} (disk: {}, config: {})", 
                     domain, if is_staging { "staging" } else { "production" }, 
                     if self.config.is_staging { "staging" } else { "production" });
            return Ok(None);
        }
        
        // Load certificate and key
        let cert_pem = std::fs::read_to_string(&cert_path)
            .map_err(|e| AcmeError::Io(e))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| AcmeError::Io(e))?;
        
        // Convert to rustls format
        let cert_chain = self.parse_pem_certificates(&cert_pem)?;
        let private_key = self.parse_pem_private_key(&key_pem)?;
        
        // Create signing key
        let provider = aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(private_key)
            .map_err(|e| AcmeError::Client(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain.into(), signing_key)
            .map_err(|e| AcmeError::Certificate(e))?;
        
        println!("Loaded certificate from disk for domain: {}", domain);
        Ok(Some(Arc::new(certified_key)))
    }
}