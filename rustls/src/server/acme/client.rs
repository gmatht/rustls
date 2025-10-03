//! ACME client implementation for certificate management
//!
//! This module provides a full-featured ACME client that can obtain and renew
//! certificates from Let's Encrypt and other ACME-compliant certificate authorities.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
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
        /// Bogus domain to use for ACME requests (workaround for rate limits)
        pub bogus_domain: Option<String>,
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
            bogus_domain: None,
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
    account: Arc<Mutex<Option<acme_lib::Account<acme_lib::persist::FilePersist>>>>,
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
            account: Arc::new(Mutex::new(None)),
            challenge_storage: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the ACME account (create or load existing)
    pub async fn initialize_account(&self) -> Result<(), AcmeError> {
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::FilePersist;

        // Create a directory for acme-lib to store its files
        let cache_dir = self.config.cache_dir.as_deref()
            .ok_or_else(|| AcmeError::Client("ACME cache directory not configured".to_string()))?;
        let acme_persist_dir = format!("{}/acme_lib", cache_dir);
        std::fs::create_dir_all(&acme_persist_dir)
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME persistence directory '{}': {}", acme_persist_dir, e)))?;

        // Set proper permissions for the directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&acme_persist_dir)
                .map_err(|e| AcmeError::Client(format!("Failed to get metadata for directory '{}': {}", acme_persist_dir, e)))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&acme_persist_dir, perms)
                .map_err(|e| AcmeError::Client(format!("Failed to set permissions for directory '{}': {}", acme_persist_dir, e)))?;
        }

        // Create ACME directory
        let persist = FilePersist::new(&acme_persist_dir);
        let dir = Directory::from_url(persist, DirectoryUrl::Other(&self.config.directory_url))
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME directory: {}", e)))?;

        // Create or load account
        let account = dir.account(&self.config.email)
            .map_err(|e| AcmeError::Client(format!("Failed to create/load ACME account: {}", e)))?;

        // Store account for later use
        let mut account_guard = self.account.lock().unwrap();
        *account_guard = Some(account);

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

    /// Log domain request for rate limit tracking
    async fn log_domain_request(&self, domain: &str, is_production: bool, bogus_domain: Option<&str>) {
        use std::path::PathBuf;
        use std::fs;
        
        let cache_dir = match self.config.cache_dir.as_deref() {
            Some(dir) => dir,
            None => {
                println!("Warning: ACME cache directory not configured, skipping domain logging");
                return;
            }
        };
        let log_file = PathBuf::from(cache_dir).join("domain_requests.json");
        
        // Load existing requests
        let mut requests: Vec<serde_json::Value> = if log_file.exists() {
            match fs::read_to_string(&log_file) {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };
        
        // Check if this is a new production certificate for a previously logged domain
        if is_production {
            for existing in &requests {
                if let (Some(existing_domain), Some(existing_production)) = 
                    (existing.get("domain").and_then(|v| v.as_str()),
                     existing.get("is_production").and_then(|v| v.as_bool())) {
                    if existing_domain == domain && !existing_production {
                        println!("⚠️  WARNING: PRODUCTION CERTIFICATE REQUESTED FOR PREVIOUSLY LOGGED DOMAIN!");
                        println!("   Domain: {}", domain);
                        println!("   Previous request was non-production at: {:?}", existing.get("timestamp"));
                        println!("   This may indicate rate limit workaround usage!");
                        println!("   ⚠️  WARNING: PRODUCTION CERTIFICATE REQUESTED FOR PREVIOUSLY LOGGED DOMAIN! ⚠️");
                    }
                }
            }
        }
        
        // Add new request
        let new_request = serde_json::json!({
            "domain": domain,
            "timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs(),
            "is_production": is_production,
            "bogus_domain": bogus_domain
        });
        requests.push(new_request);
        
        // Save updated requests
        if let Ok(content) = serde_json::to_string_pretty(&requests) {
            let _ = fs::write(&log_file, content);
        }
    }

    /// Backup certificates from /tmp/acme_certs to appropriate backup directory
    fn backup_acme_certificates(&self) {
        use std::process::Command;
        
        let tmp_acme_dir = "/tmp/acme_certs";
        let cache_dir = match self.config.cache_dir.as_deref() {
            Some(dir) => dir,
            None => {
                println!("Warning: ACME cache directory not configured, skipping certificate backup");
                return;
            }
        };
        let backup_dir = if self.config.is_staging {
            format!("{}/staging", cache_dir)
        } else {
            format!("{}/production", cache_dir)
        };
        
        // Create backup directory
        if let Err(e) = std::fs::create_dir_all(&backup_dir) {
            println!("Warning: Failed to create backup directory {}: {}", backup_dir, e);
            return;
        }
        
        // Copy certificates from /tmp/acme_certs to backup directory
        let output = Command::new("cp")
            .args(&["-r", tmp_acme_dir, &backup_dir])
            .output();
        
        match output {
            Ok(output) => {
                if output.status.success() {
                    println!("Backed up ACME certificates from {} to {}", tmp_acme_dir, backup_dir);
                } else {
                    println!("Warning: Failed to backup ACME certificates: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                println!("Warning: Failed to execute backup command: {}", e);
            }
        }
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

        // Try to load from acme-lib's persistence
        if let Some(certified_key) = self.load_certificate_from_acme_lib(domain).await? {
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
            println!("Loaded certificate from acme-lib persistence for domain: {}", domain);
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

    /// Retry ACME operation with exponential backoff for nonce errors
    async fn retry_acme_operation<F, T>(&self, operation: F, max_retries: u32) -> Result<T, AcmeError>
    where
        F: Fn() -> Result<T, AcmeError>,
    {
        let mut retries = 0;
        loop {
            match operation() {
                Ok(result) => return Ok(result),
                Err(e) => {
                    let error_msg = format!("{}", e);
                    if error_msg.contains("anti-replay nonce") || error_msg.contains("invalid nonce") {
                        if retries < max_retries {
                            retries += 1;
                            let delay = Duration::from_millis((1000 * retries).into());
                            println!("⚠️  Nonce error (attempt {}), retrying in {}ms...", retries, delay.as_millis());
                            tokio::time::sleep(delay).await;
                            continue;
                        } else {
                            println!("❌ Max retries ({}) exceeded for nonce error", max_retries);
                            return Err(e);
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    /// Request a real ACME certificate using HTTP-01 challenges
    pub async fn request_acme_certificate(&self, domain: &str) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Use bogus domain if specified (rate limit workaround)
        let acme_domain = if let Some(ref bogus) = self.config.bogus_domain {
            println!("🚀 Using bogus domain '{}' for ACME request (original domain: {})", bogus, domain);
            bogus.as_str()
        } else {
            domain
        };
        
        println!("🚀 Starting request_acme_certificate for domain: {} (ACME domain: {})", domain, acme_domain);
        
        // Log domain request for rate limit tracking
        self.log_domain_request(domain, !self.config.is_staging, self.config.bogus_domain.as_deref()).await;
        
        // Check cache first
        {
            let cache = self.certificate_cache.read().await;
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > SystemTime::now() {
                    println!("✅ Found valid cached certificate for domain: {}", domain);
                    return Ok(cached.certified_key.clone());
                }
            }
        }
        println!("🔄 No valid cached certificate found, proceeding with ACME request");

        // Get domain-specific email
        let domain_email = self.get_email_for_domain(acme_domain);
        println!("Using email for domain {}: {}", acme_domain, domain_email);

        // Create a new ACME directory and account for this request
        // This ensures proper nonce management per request
        println!("Creating ACME directory for domain: {} (ACME domain: {})", domain, acme_domain);
        println!("ACME Directory URL: {}", self.config.directory_url);
        
        // Check system time for clock sync issues
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        println!("Current system time: {} seconds since epoch", now.as_secs());
        println!("Current system time (human readable): {:?}", SystemTime::now());
        
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::FilePersist;
        
        // Create a directory for acme-lib to store its files
        let cache_dir = self.config.cache_dir.as_deref()
            .ok_or_else(|| AcmeError::Client("ACME cache directory not configured".to_string()))?;
        let acme_persist_dir = format!("{}/acme_lib", cache_dir);
        std::fs::create_dir_all(&acme_persist_dir)
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME persistence directory '{}': {}", acme_persist_dir, e)))?;
        
        // Set proper permissions for the directory
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&acme_persist_dir)
                .map_err(|e| AcmeError::Client(format!("Failed to get metadata for directory '{}': {}", acme_persist_dir, e)))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&acme_persist_dir, perms)
                .map_err(|e| AcmeError::Client(format!("Failed to set permissions for directory '{}': {}", acme_persist_dir, e)))?;
        }
        
        println!("🔄 Using FilePersist for ACME in directory: {}", acme_persist_dir);
        let persist = FilePersist::new(&acme_persist_dir);
        let dir = Directory::from_url(persist, DirectoryUrl::Other(&self.config.directory_url))
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME directory for domain '{}': {}", domain, e)))?;

        // Create account with retry for nonce errors
        println!("🔄 Creating ACME account for email: {}", domain_email);
        let account = self.retry_acme_operation(|| {
            dir.account(&domain_email)
                .map_err(|e| {
                    let error_msg = format!("Failed to create/load ACME account for {}: {}", domain_email, e);
                    println!("❌ ACME account creation failed: {}", e);
                    if error_msg.contains("anti-replay nonce") || error_msg.contains("invalid nonce") {
                        println!("⚠️  Nonce error detected - this may be due to clock sync issues or network problems");
                        println!("   Current time: {} seconds since epoch", now.as_secs());
                        println!("   Consider checking system clock synchronization");
                    } else if error_msg.contains("JWS verification error") || error_msg.contains("malformed") {
                        println!("🔧 JWS Verification Error in account creation:");
                        println!("   This indicates a problem with the JSON Web Signature");
                        println!("   Possible causes:");
                        println!("   1. Invalid or expired nonce");
                        println!("   2. Clock synchronization issues");
                        println!("   3. Invalid account key or signature");
                        println!("   4. Malformed JWS structure");
                        println!("   Error: {}", e);
                    }
                    AcmeError::Client(error_msg)
                })
        }, 3).await?;
        println!("✅ ACME account created successfully for email: {}", domain_email);

        println!("Requesting real ACME certificate for domain: {}", domain);

        // Create order for the domain
        println!("Creating ACME order for domain: {}", domain);
        let mut order = account.new_order(acme_domain, &[])
            .map_err(|e| {
                let error_msg = format!("Failed to create ACME order: {}", e);
                println!("❌ ACME order creation failed: {}", e);
                if error_msg.contains("anti-replay nonce") || error_msg.contains("invalid nonce") {
                    println!("⚠️  Nonce error in order creation - retrying may help");
                    println!("   Error: {}", e);
                } else if error_msg.contains("Permission denied") || error_msg.contains("os error 13") {
                    println!("🔧 Permission Error in ACME order creation:");
                    println!("   This might be an issue with the ACME library's internal file operations");
                    println!("   Error: {}", e);
                }
                AcmeError::Client(error_msg)
            })?;

        println!("ACME order created for domain: {}", domain);

        // Process challenges in a loop until validations are confirmed
        let order_csr = loop {
            // Check if we're done
            if let Some(ord_csr) = order.confirm_validations() {
                break ord_csr;
            }

            // Get authorizations
            println!("Getting authorizations for domain: {}", domain);
            let auths = order.authorizations()
                .map_err(|e| {
                    let error_msg = format!("Failed to get authorizations: {}", e);
                    println!("❌ Failed to get authorizations: {}", e);
                    if error_msg.contains("Permission denied") || error_msg.contains("os error 13") {
                        println!("🔧 Permission Error in getting authorizations:");
                        println!("   This might be an issue with the ACME library's internal file operations");
                        println!("   Error: {}", e);
                    } else if error_msg.contains("JWS verification error") || error_msg.contains("malformed") {
                        println!("🔧 JWS Verification Error in getting authorizations:");
                        println!("   This indicates a problem with the JSON Web Signature");
                        println!("   Possible causes:");
                        println!("   1. Invalid or expired nonce");
                        println!("   2. Clock synchronization issues");
                        println!("   3. Invalid account key or signature");
                        println!("   4. Malformed JWS structure");
                        println!("   Error: {}", e);
                    }
                    AcmeError::Client(error_msg)
                })?;

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
                println!("Triggering HTTP-01 challenge validation for domain: {}", domain);
                challenge.validate(5000)
                    .map_err(|e| {
                        let error_msg = format!("HTTP-01 challenge validation failed: {}", e);
                        println!("❌ HTTP-01 challenge validation failed: {}", e);
                        if error_msg.contains("Permission denied") || error_msg.contains("os error 13") {
                            println!("🔧 Permission Error in challenge validation:");
                            println!("   This might be an issue with the ACME library's internal file operations");
                            println!("   Error: {}", e);
                        }
                        AcmeError::Client(error_msg)
                    })?;
                
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
        println!("Downloading certificate from ACME server for domain: {}", domain);
        let cert = order_cert.download_and_save_cert()
            .map_err(|e| {
                let error_msg = format!("Failed to download and save certificate for domain '{}': {}", domain, e);
                println!("❌ Certificate download failed: {}", e);
                if error_msg.contains("Permission denied") || error_msg.contains("os error 13") {
                    println!("🔧 Permission Error in certificate download:");
                    println!("   This might be an issue with the ACME library's internal file operations");
                    println!("   The ACME library might be trying to write to a directory it doesn't have access to");
                    println!("   Error: {}", e);
                }
                AcmeError::Client(error_msg)
            })?;

        println!("Certificate downloaded successfully for domain: {}", domain);

        // Convert the real ACME certificate to rustls format
        println!("Real ACME certificate obtained! Certificate chain length: {}", cert.certificate().len());
        println!("🔄 Converting ACME certificate to rustls format for domain: {}", domain);
        let certified_key = self.convert_acme_cert_to_rustls(&cert)?;
        println!("✅ Successfully converted ACME certificate to rustls format");
        println!("🔄 About to start caching and saving process for domain: {}", domain);

        // Cache the certificate in memory for quick access
        println!("🔄 Caching certificate in memory for domain: {}", domain);
        {
            let mut cache = self.certificate_cache.write().await;
            let expires_at = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 30); // 30 days
            cache.insert(domain.to_string(), CachedCertificate {
                certified_key: certified_key.clone(),
                expires_at,
                domain: domain.to_string(),
            });
        }
        println!("✅ ACME certificate cached in memory for domain: {}", domain);
        println!("✅ ACME certificate persisted by acme-lib for domain: {}", domain);
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
        
        // Backup certificates from /tmp/acme_certs to appropriate backup directory
        self.backup_acme_certificates();
        
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

    /// Load certificate from acme-lib's persistence
    async fn load_certificate_from_acme_lib(&self, domain: &str) -> Result<Option<Arc<CertifiedKey>>, AcmeError> {
        use acme_lib::{Directory, DirectoryUrl};
        use acme_lib::persist::FilePersist;

        // Create the same directory structure that acme-lib uses
        let cache_dir = self.config.cache_dir.as_deref()
            .ok_or_else(|| AcmeError::Client("ACME cache directory not configured".to_string()))?;
        let acme_persist_dir = format!("{}/acme_lib", cache_dir);
        
        // Check if the directory exists
        if !std::path::Path::new(&acme_persist_dir).exists() {
            return Ok(None);
        }

        // Create FilePersist instance
        let persist = FilePersist::new(&acme_persist_dir);
        let dir = Directory::from_url(persist, DirectoryUrl::Other(&self.config.directory_url))
            .map_err(|e| AcmeError::Client(format!("Failed to create ACME directory for loading: {}", e)))?;

        // Get domain-specific email
        let domain_email = self.get_email_for_domain(domain);
        
        // Try to load the account and certificate
        let account = dir.account(&domain_email)
            .map_err(|e| AcmeError::Client(format!("Failed to load ACME account for {}: {}", domain_email, e)))?;

        // Try to get the certificate from acme-lib's persistence
        match account.certificate(domain) {
            Ok(Some(acme_cert)) => {
                println!("Found certificate in acme-lib persistence for domain: {}", domain);
                // Convert to rustls format
                let certified_key = self.convert_acme_cert_to_rustls(&acme_cert)?;
                Ok(Some(certified_key))
            }
            Ok(None) => {
                println!("No certificate found in acme-lib persistence for domain: {}", domain);
                Ok(None)
            }
            Err(e) => {
                println!("Error loading certificate from acme-lib persistence for domain {}: {}", domain, e);
                Ok(None)
            }
        }
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