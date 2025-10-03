//! On-demand certificate resolver with ACME integration
//!
//! This module provides a ResolvesServerCert implementation that can dynamically
//! obtain certificates from ACME providers based on the requested domain name.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use std::string::String;
use std::format;
use std::string::ToString;
use std::boxed::Box;
use std::vec;
use std::println;

use crate::server::{ClientHello, ResolvesServerCert};
use crate::sign::{CertifiedKey, CertifiedSigner};
use crate::Error;

#[cfg(feature = "acme")]
use {
    super::client::{AcmeClient, AcmeError},
    super::validation::{DnsValidator, ValidationResult},
    tokio::sync::RwLock,
};

/// On-demand certificate resolver that integrates with ACME
pub struct OnDemandCertResolver {
    /// ACME client for certificate management
    acme_client: Arc<AcmeClient>,
    /// DNS validator for domain ownership verification
    dns_validator: Arc<DnsValidator>,
    /// Certificate cache
    cert_cache: Arc<RwLock<HashMap<String, CachedCertificate>>>,
    /// Fallback resolver for non-ACME domains
    fallback_resolver: Option<Arc<dyn ResolvesServerCert + Send + Sync>>,
    /// Maximum cache size
    max_cache_size: usize,
    /// Certificate renewal threshold
    renewal_threshold: Duration,
}

/// Cached certificate with metadata
#[derive(Debug, Clone)]
struct CachedCertificate {
    certified_key: Arc<CertifiedKey>,
    expires_at: SystemTime,
    domain: String,
    created_at: SystemTime,
}

impl OnDemandCertResolver {
    /// Create a new on-demand certificate resolver
    pub fn new(
        acme_client: Arc<AcmeClient>,
        dns_validator: Arc<DnsValidator>,
        fallback_resolver: Option<Arc<dyn ResolvesServerCert + Send + Sync>>,
        max_cache_size: usize,
        renewal_threshold: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            acme_client,
            dns_validator,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            fallback_resolver,
            max_cache_size,
            renewal_threshold,
        })
    }

    /// Create a new resolver with fallback certificate resolver
    pub fn with_fallback(
        acme_client: Arc<AcmeClient>,
        dns_validator: Arc<DnsValidator>,
        fallback: Arc<dyn ResolvesServerCert + Send + Sync>,
        max_cache_size: usize,
        renewal_threshold: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            acme_client,
            dns_validator,
            cert_cache: Arc::new(RwLock::new(HashMap::new())),
            fallback_resolver: Some(fallback),
            max_cache_size,
            renewal_threshold,
        })
    }

    /// Set the maximum cache size
    pub fn set_max_cache_size(&mut self, size: usize) {
        self.max_cache_size = size;
    }

    /// Set the renewal threshold
    pub fn set_renewal_threshold(&mut self, threshold: Duration) {
        self.renewal_threshold = threshold;
    }

    /// Get certificate statistics
    pub async fn stats(&self) -> CertificateStats {
        let cache = self.cert_cache.read().await;
        let now = SystemTime::now();

        let total = cache.len();
        let expired = cache.values()
            .filter(|c| c.expires_at <= now)
            .count();
        let expiring_soon = cache.values()
            .filter(|c| c.expires_at > now && c.expires_at <= now + self.renewal_threshold)
            .count();

        CertificateStats {
            total,
            expired,
            expiring_soon,
            active: total - expired,
        }
    }

    /// Clean expired certificates from cache
    pub async fn clean_expired_certificates(&self) -> Result<usize, AcmeError> {
        let mut cache = self.cert_cache.write().await;
        let now = SystemTime::now();
        let initial_count = cache.len();
        
        cache.retain(|_, cert| cert.expires_at > now);
        
        Ok(initial_count - cache.len())
    }

    /// Manually add a certificate to the cache
    pub async fn add_certificate(
        &self,
        domain: &str,
        certified_key: Arc<CertifiedKey>,
        expires_at: SystemTime,
    ) -> Result<(), AcmeError> {
        let mut cache = self.cert_cache.write().await;
        
        // Check cache size limit
        if cache.len() >= self.max_cache_size {
            // Remove oldest certificate
            let oldest_domain = cache.iter()
                .min_by_key(|(_, cert)| cert.created_at)
                .map(|(domain, _)| domain.clone());
            
            if let Some(domain) = oldest_domain {
                cache.remove(&domain);
            }
        }
        
        let cached_cert = CachedCertificate {
            certified_key,
            expires_at,
            domain: domain.to_string(),
            created_at: SystemTime::now(),
        };

        cache.insert(domain.to_string(), cached_cert);
        Ok(())
    }

    /// Get or create a certificate for the given domain
    async fn get_or_create_certificate(&self, domain: &str) -> Result<Arc<CertifiedKey>, AcmeError> {
        // Check cache first
        {
            let cache = self.cert_cache.read().await;
            if let Some(cached) = cache.get(domain) {
                if cached.expires_at > SystemTime::now() {
                    return Ok(cached.certified_key.clone());
                }
            }
        }

        // Perform DNS validation
        let validation_result = self.dns_validator.validate_domain(domain).await;
        match validation_result {
            ValidationResult::Valid => {
                // Domain is authorized, try to get certificate from ACME (this will check cache first)
                match self.acme_client.get_certificate(domain).await {
                    Ok(certified_key) => {
                        // Cache the certificate
                        let expires_at = SystemTime::now() + Duration::from_secs(60 * 60 * 24 * 30); // 30 days
                        let mut cache = self.cert_cache.write().await;
                        cache.insert(domain.to_string(), CachedCertificate {
                            certified_key: certified_key.clone(),
                            expires_at,
                            domain: domain.to_string(),
                            created_at: SystemTime::now(),
                        });
                        Ok(certified_key)
                    }
                    Err(e) => {
                        // Check if this is a domain (has dots) - if so, don't allow self-signed fallback
                        if domain.contains('.') {
                            println!("ACME certificate request failed for domain {}: {}", domain, e);
                            println!("Error details: {}", e);
                            
                            // Check for specific error types and provide helpful suggestions
                            if let AcmeError::Client(msg) = &e {
                                println!("ACME Client Error: {}", msg);
                                if msg.contains("anti-replay nonce") || msg.contains("invalid nonce") {
                                    println!("🔧 Nonce Error Troubleshooting:");
                                    println!("   1. Check system clock synchronization: ntpdate -s time.nist.gov");
                                    println!("   2. Verify network connectivity to ACME server");
                                    println!("   3. Try using a different ACME directory URL");
                                    println!("   4. Wait a few minutes and retry");
                                }
                            } else if let AcmeError::Io(io_err) = &e {
                                println!("IO Error: {}", io_err);
                            } else if let AcmeError::Validation(msg) = &e {
                                println!("Validation Error: {}", msg);
                            }
                            println!("❌ Self-signed certificates are not allowed for domains. ACME certificate required for: {}", domain);
                            return Err(AcmeError::Validation(format!("ACME certificate required for domain: {}. Self-signed certificates are not allowed for domains.", domain)));
                        } else {
                            // Allow self-signed certificates for IP addresses and hostnames without dots
                            println!("ACME certificate request failed for {}: {}", domain, e);
                            println!("Falling back to self-signed certificate for: {}", domain);
                            self.generate_self_signed_certificate(domain)
                        }
                    }
                }
            }
            ValidationResult::InvalidIp => Err(AcmeError::Validation(format!("Domain {} resolves to unauthorized IPs", domain))),
            ValidationResult::NoResolution => Err(AcmeError::Validation(format!("Domain {} does not resolve to any IP address", domain))),
            ValidationResult::Timeout => Err(AcmeError::Validation(format!("DNS resolution timeout for domain {}", domain))),
            ValidationResult::Error(msg) => Err(AcmeError::Validation(format!("DNS validation error for domain {}: {}", domain, msg))),
        }
    }

    /// Check if a certificate needs renewal
    pub async fn needs_renewal(&self, domain: &str) -> bool {
        let cache = self.cert_cache.read().await;
        if let Some(cached) = cache.get(domain) {
            return cached.expires_at <= SystemTime::now() + self.renewal_threshold;
        }
        true // No certificate means it needs renewal
    }

    /// Renew a certificate if needed
    pub async fn renew_if_needed(&self, domain: &str) -> Result<Option<Arc<CertifiedKey>>, AcmeError> {
        if self.needs_renewal(domain).await {
            println!("Renewing certificate for domain: {}", domain);
            let new_cert = self.get_or_create_certificate(domain).await?;
            Ok(Some(new_cert))
        } else {
            Ok(None)
        }
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
        
        let cert_chain = vec![pki_types::CertificateDer::from(cert_der)].into();
        let key = pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        
        // Create a simple signing key using the default provider
        let provider = crate::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| AcmeError::Client(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain, signing_key)
            .map_err(|e| AcmeError::Certificate(e))?;
        
        Ok(Arc::new(certified_key))
    }

    /// Generate a self-signed certificate for IP address connections
    fn generate_self_signed_certificate_for_ip(&self) -> Result<Arc<CertifiedKey>, Error> {
        // Use rcgen's simple self-signed certificate generation
        let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| Error::General(format!("Failed to generate self-signed certificate: {}", e)))?;
        
        // Convert to rustls format
        let cert_der = cert.der().clone();
        let key_der = signing_key.serialize_der();
        
        let cert_chain = vec![pki_types::CertificateDer::from(cert_der)].into();
        let key = pki_types::PrivateKeyDer::Pkcs8(key_der.into());
        
        // Create a simple signing key using the default provider
        let provider = crate::crypto::aws_lc_rs::default_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|e| Error::General(format!("Failed to create signing key: {}", e)))?;
        
        let certified_key = CertifiedKey::new(cert_chain, signing_key)
            .map_err(|e| Error::General(format!("Failed to create certified key: {}", e)))?;
        
        Ok(Arc::new(certified_key))
    }
}

impl std::fmt::Debug for OnDemandCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandCertResolver")
            .field("max_cache_size", &self.max_cache_size)
            .field("renewal_threshold", &self.renewal_threshold)
            .finish()
    }
}

impl ResolvesServerCert for OnDemandCertResolver {
    fn resolve(&self, client_hello: &ClientHello<'_>) -> Result<CertifiedSigner, Error> {
        let Some(server_name) = client_hello.server_name() else {
            // No server name provided (IP address connection) - generate self-signed certificate
            println!("No server name provided (IP address connection), generating self-signed certificate");
            return self.generate_self_signed_certificate_for_ip()
                .and_then(|cert| cert.signer(client_hello.signature_schemes())
                    .ok_or(Error::NoSuitableCertificate));
        };

        let domain = server_name.as_ref();

        // Try to get certificate from cache first (synchronous)
        let cached_cert = {
            let cache = self.cert_cache.try_read().ok();
            if let Some(cache) = cache {
                if let Some(cached) = cache.get(domain) {
                    if cached.expires_at > SystemTime::now() {
                        Some(cached.certified_key.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(certified_key) = cached_cert {
            return certified_key.signer(client_hello.signature_schemes())
                .ok_or(Error::NoSuitableCertificate);
        }

        // Use tokio runtime to handle async operations
        let rt = match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle,
            Err(_) => {
                // No tokio runtime available, create a new one
                match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt.handle().clone(),
                    Err(_) => {
                        // Check if this is a domain (has dots) - if so, don't allow self-signed fallback
                        if domain.contains('.') {
                            println!("❌ No tokio runtime available and self-signed certificates are not allowed for domains: {}", domain);
                            return Err(Error::General(format!("ACME certificate required for domain: {}. Self-signed certificates are not allowed for domains.", domain)));
                        } else {
                            // Allow self-signed certificates for IP addresses and hostnames without dots
                            println!("No tokio runtime available, generating self-signed certificate for: {}", domain);
                            return self.generate_self_signed_certificate(domain)
                                .and_then(|cert| cert.signer(client_hello.signature_schemes())
                                    .ok_or(AcmeError::Certificate(Error::NoSuitableCertificate)))
                                .map_err(|e| Error::General(format!("Certificate generation failed: {}", e)));
                        }
                    }
                }
            }
        };

        // Run async operations in the tokio runtime
        match rt.block_on(self.get_or_create_certificate(domain)) {
            Ok(certified_key) => {
                println!("Certificate obtained for domain: {}", domain);
                certified_key.signer(client_hello.signature_schemes())
                    .ok_or(Error::NoSuitableCertificate)
            }
            Err(e) => {
                println!("Certificate creation failed for {}: {}, trying fallback", domain, e);
                // Try fallback resolver if available
                if let Some(fallback) = &self.fallback_resolver {
                    fallback.resolve(client_hello)
                } else {
                    // Check if this is a domain (has dots) - if so, don't allow self-signed fallback
                    if domain.contains('.') {
                        println!("❌ Self-signed certificates are not allowed for domains: {}", domain);
                        Err(Error::General(format!("ACME certificate required for domain: {}. Self-signed certificates are not allowed for domains.", domain)))
                    } else {
                        // Allow self-signed certificates for IP addresses and hostnames without dots
                        println!("Generating self-signed certificate for: {}", domain);
                        self.generate_self_signed_certificate(domain)
                            .and_then(|cert| cert.signer(client_hello.signature_schemes())
                                .ok_or(AcmeError::Certificate(Error::NoSuitableCertificate)))
                            .map_err(|e| Error::General(format!("Certificate generation failed: {}", e)))
                    }
                }
            }
        }
    }
}

/// Certificate statistics
#[derive(Debug, Clone)]
pub struct CertificateStats {
    pub total: usize,
    pub active: usize,
    pub expired: usize,
    pub expiring_soon: usize,
}
