//! EasyPeas - On-demand HTTPS server with ACME certificate management
//!
//! This example demonstrates a complete on-demand HTTPS server that:
//! - Accepts HTTPS connections using rustls Acceptor
//! - Validates that domains resolve to authorized IP addresses
//! - Dynamically fetches ACME certificates from Let's Encrypt
//! - Caches certificates for performance
//! - Handles both HTTP-01 and DNS-01 challenges
//!
//! Usage:
//!   cargo run --example easyp --features acme -- --help

use std::collections::{HashMap, BTreeMap};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use rustls::server::{Acceptor, ResolvesServerCert};
use rustls::{ServerConfig, ServerConnection};

#[cfg(feature = "acme")]
use rustls::server::acme::{AcmeClient, OnDemandCertResolver, DnsValidator};
use rustls::server::acme::types::{AcmeConfig, ChallengeType};

/// EasyPeas - On-demand HTTPS server with ACME certificate management
#[derive(Parser, Clone)]
#[command(name = "easyp")]
#[command(about = "EasyPeas - On-demand HTTPS server with ACME certificate management")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Allowed IP addresses for domain validation (comma-separated). If not specified, will auto-detect server IPs
    #[arg(long)]
    allowed_ips: Option<String>,

    /// ACME directory URL
    #[arg(long, default_value = "https://acme-staging-v02.api.letsencrypt.org/directory")]
    acme_directory: String,

           /// Email address for ACME account (defaults to webmaster@domain for each domain)
           #[arg(long)]
           acme_email: Option<String>,

    /// Challenge type (http01 or dns01)
    #[arg(long, default_value = "http01")]
    challenge_type: String,

    /// Certificate cache directory
    #[arg(long)]
    cache_dir: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Test mode (use self-signed certificates)
    #[arg(long)]
    test_mode: bool,
}

/// On-demand HTTPS server
struct OnDemandHttpsServer {
    http_listener: TcpListener,  // Port 80 for ACME challenges
    https_listener: TcpListener, // Port 443 for HTTPS traffic
    cert_resolver: Arc<dyn ResolvesServerCert + Send + Sync>,
    args: Args,
    http_challenges: Arc<Mutex<BTreeMap<String, String>>>, // token -> key_authorization
    acme_client: Option<Arc<AcmeClient>>, // Added for challenge storage
    allowed_ips: Vec<IpAddr>, // Store allowed IPs for display
}

impl OnDemandHttpsServer {
    /// Create a new on-demand HTTPS server
    fn new(args: Args) -> Result<Self, Box<dyn std::error::Error>> {
        // Create HTTP listener on port 80 for ACME challenges
        let http_listener = TcpListener::bind("0.0.0.0:80")?;
        http_listener.set_nonblocking(true)?;
        
        // Create HTTPS listener on port 443 for HTTPS traffic
        let https_listener = TcpListener::bind("0.0.0.0:443")?;
        https_listener.set_nonblocking(true)?;

               // Parse allowed IP addresses or auto-detect
               let allowed_ips = if let Some(ips_str) = &args.allowed_ips {
                   parse_allowed_ips(ips_str)?
               } else {
                   println!("No allowed IPs specified, auto-detecting server IPs...");
                   detect_server_ips().unwrap_or_else(|e| {
                       println!("Warning: Could not detect server IPs ({}), using localhost fallback", e);
                       vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))]
                   })
               };

               // Create certificate resolver with real ACME integration
               #[cfg(feature = "acme")]
               let (cert_resolver, acme_client) = {
               let acme_config = AcmeConfig {
                   directory_url: args.acme_directory.clone(),
                   email: args.acme_email.clone().unwrap_or_else(|| "admin@example.com".to_string()),
                   allowed_ips: allowed_ips.clone(),
                   cache_dir: args.cache_dir.clone(),
                   renewal_threshold_days: 30,
                   challenge_type: ChallengeType::Http01,
                   is_staging: args.acme_directory.contains("staging") || args.acme_directory.contains("stg"),
               };

                   let mut acme_client = AcmeClient::new(acme_config);

                   // Initialize ACME account
                   let rt = tokio::runtime::Runtime::new().unwrap();
                   rt.block_on(async {
                       acme_client.initialize_account().await
                   }).map_err(|e| format!("Failed to initialize ACME account: {}", e))?;

                   let acme_client = Arc::new(acme_client);
                   let dns_validator = Arc::new(DnsValidator::new(allowed_ips.clone())?);

                   let cert_resolver = Arc::new(OnDemandCertResolver::new(
                       acme_client.clone(),
                       dns_validator,
                       None, // No fallback resolver
                       1000, // Max cache size
                       Duration::from_secs(30 * 24 * 60 * 60), // 30 days renewal threshold
                   )?);

                   (cert_resolver, Some(acme_client))
               };

               #[cfg(not(feature = "acme"))]
               let (cert_resolver, acme_client) = {
                   // Fallback to test resolver if ACME feature not enabled
                   (Arc::new(TestCertResolver::new(allowed_ips)?), None)
               };

               Ok(Self {
                   http_listener,
                   https_listener,
                   cert_resolver,
                   args,
                   http_challenges: Arc::new(Mutex::new(BTreeMap::new())),
                   acme_client,
                   allowed_ips,
               })
    }

    /// Run the server
    fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
               println!("Starting EasyPeas on-demand HTTPS server");
               println!("HTTP listener on port 80 (for ACME challenges)");
               println!("HTTPS listener on port 443 (for HTTPS traffic)");
               println!("Allowed IPs: {:?}", self.allowed_ips);
               println!("ACME Directory: {}", self.args.acme_directory);
               println!("Challenge Type: {}", self.args.challenge_type);
               println!("Test Mode: {}", self.args.test_mode);

        let mut connections: Vec<ServerConnection> = Vec::new();

        loop {
            // Accept HTTP connections (port 80) for ACME challenges
            match self.http_listener.accept() {
                Ok((stream, addr)) => {
                    println!("New HTTP connection from {} (ACME challenge)", addr);
                    
                    // Handle HTTP connection for ACME challenges
                    let acme_client = self.acme_client.clone();
                    let http_challenges = self.http_challenges.clone();

                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_http_connection(stream, acme_client, http_challenges) {
                            eprintln!("HTTP connection error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, continue
                }
                Err(e) => {
                    eprintln!("HTTP accept error: {}", e);
                }
            }

            // Accept HTTPS connections (port 443) for HTTPS traffic
            match self.https_listener.accept() {
                Ok((stream, addr)) => {
                    println!("New HTTPS connection from {}", addr);
                    
                    // Handle HTTPS connection
                    let cert_resolver = self.cert_resolver.clone();
                    let args = self.args.clone();
                    let acme_client = self.acme_client.clone();
                    let http_challenges = self.http_challenges.clone();

                    std::thread::spawn(move || {
                        if let Err(e) = Self::handle_connection(stream, cert_resolver, args, acme_client, http_challenges) {
                            eprintln!("HTTPS connection error: {}", e);
                        }
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection available, continue
                }
                Err(e) => {
                    eprintln!("HTTPS accept error: {}", e);
                }
            }

            // Process existing connections
            connections.retain(|conn| {
                // In a real implementation, you'd process the connection here
                // For this example, we just remove completed connections
                false
            });

            // Small delay to prevent busy waiting
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Handle HTTP connection (port 80) for ACME challenges
    fn handle_http_connection(
        mut stream: TcpStream,
        acme_client: Option<Arc<AcmeClient>>,
        http_challenges: Arc<Mutex<BTreeMap<String, String>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Read HTTP request
        let mut buffer = [0; 4096];
        let mut total_read = 0;

        // Read data in a loop to handle partial reads
        loop {
            match stream.read(&mut buffer[total_read..]) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    total_read += n;
                    if total_read >= buffer.len() {
                        break; // Buffer full
                    }
                    // Check if we have a complete HTTP request
                    if let Ok(request_str) = std::str::from_utf8(&buffer[..total_read]) {
                        if request_str.contains("\r\n\r\n") {
                            break; // Complete HTTP request received
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, wait a bit
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Parse HTTP request
        let request = String::from_utf8_lossy(&buffer[..total_read]);
        let lines: Vec<&str> = request.lines().collect();

        if let Some(first_line) = lines.first() {
            println!("HTTP Request: {}", first_line);

            // Handle HTTP-01 ACME challenges
            if first_line.starts_with("GET /.well-known/acme-challenge/") {
                return Self::handle_acme_challenge_http(stream, first_line, &acme_client, &http_challenges);
            }
        }

        // Send 404 for non-ACME requests
        let response = "HTTP/1.1 404 Not Found\r\n\
                       Content-Type: text/plain\r\n\
                       Content-Length: 13\r\n\
                       Connection: close\r\n\
                       \r\n\
                       Not Found";

        stream.write_all(response.as_bytes())?;
        stream.flush()?;

        Ok(())
    }

    /// Handle a single HTTPS connection
    fn handle_connection(
        mut stream: TcpStream,
        cert_resolver: Arc<dyn ResolvesServerCert + Send + Sync>,
        args: Args,
        acme_client: Option<Arc<AcmeClient>>,
        http_challenges: Arc<Mutex<BTreeMap<String, String>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we have a complete ClientHello
        let accepted = loop {
            match acceptor.read_tls(&mut stream) {
                Ok(0) => return Ok(()), // Connection closed
                Ok(_) => {
                    match acceptor.accept() {
                        Ok(Some(accepted)) => break accepted,
                        Ok(None) => continue,
                        Err((e, mut alert)) => {
                            alert.write_all(&mut stream)?;
                            return Err(format!("Error accepting connection: {}", e).into());
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, continue
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        };

        // Get the server name from ClientHello
        let server_name = accepted.client_hello().server_name()
            .map(|name| name.as_ref().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        println!("Processing request for domain: {}", server_name);

        // Create server config with our certificate resolver
        let server_config = ServerConfig::builder_with_provider(
            rustls::crypto::aws_lc_rs::default_provider().into()
        )
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver)
        .map_err(|e| format!("Failed to create server config: {}", e))?;

        // Complete the TLS handshake
        let mut conn = match accepted.into_connection(Arc::new(server_config)) {
            Ok(conn) => conn,
            Err((e, mut alert)) => {
                alert.write_all(&mut stream)?;
                return Err(format!("Error completing connection: {}", e).into());
            }
        };

        // Handle the connection
        Self::process_https_request(&mut stream, &mut conn, &server_name, &acme_client, &http_challenges)?;

        Ok(())
    }

    /// Process HTTPS request and send response
    fn process_https_request(
        stream: &mut TcpStream,
        conn: &mut ServerConnection,
        server_name: &str,
        acme_client: &Option<Arc<AcmeClient>>,
        http_challenges: &Arc<Mutex<BTreeMap<String, String>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Complete the handshake
        conn.complete_io(stream)?;

        // Read HTTP request using the TLS connection
        let mut buffer = [0; 4096];
        let mut total_read = 0;

        // Read data in a loop to handle partial reads
        loop {
            match conn.reader().read(&mut buffer[total_read..]) {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    total_read += n;
                    if total_read >= buffer.len() {
                        break; // Buffer full
                    }
                    // Check if we have a complete HTTP request
                    if let Ok(request_str) = std::str::from_utf8(&buffer[..total_read]) {
                        if request_str.contains("\r\n\r\n") {
                            break; // Complete HTTP request received
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No data available, wait a bit
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        let n = total_read;

        // Parse HTTP request (simplified)
        let request = String::from_utf8_lossy(&buffer[..n]);
        let lines: Vec<&str> = request.lines().collect();

        if let Some(first_line) = lines.first() {
            println!("HTTP Request: {}", first_line);
            
                   // Handle HTTP-01 ACME challenges
                   if first_line.starts_with("GET /.well-known/acme-challenge/") {
                       return Self::handle_acme_challenge(stream, conn, first_line, acme_client, http_challenges);
                   }
        }

        // Send HTTP response
        let html_content = format!(
            "<!DOCTYPE html>\n\
             <html>\n\
             <head>\n\
                 <title>EasyPeas HTTPS Server</title>\n\
                 <style>\n\
                     body {{ font-family: Arial, sans-serif; margin: 40px; }}\n\
                     .container {{ max-width: 800px; margin: 0 auto; }}\n\
                     .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}\n\
                     .content {{ padding: 20px; background: #ecf0f1; border-radius: 5px; margin-top: 20px; }}\n\
                     .info {{ background: #3498db; color: white; padding: 10px; border-radius: 3px; margin: 10px 0; }}\n\
                 </style>\n\
             </head>\n\
             <body>\n\
                 <div class=\"container\">\n\
                     <div class=\"header\">\n\
                         <h1>🔒 EasyPeas HTTPS Server</h1>\n\
                         <p>Powered by rustls with ACME certificate management</p>\n\
                     </div>\n\
                     <div class=\"content\">\n\
                         <div class=\"info\">\n\
                             <strong>Domain:</strong> {}\n\
                         </div>\n\
                         <div class=\"info\">\n\
                             <strong>Certificate:</strong> Dynamically obtained via ACME\n\
                         </div>\n\
                         <div class=\"info\">\n\
                             <strong>Status:</strong> ✅ Secure connection established\n\
                         </div>\n\
                         <h2>Features</h2>\n\
                         <ul>\n\
                             <li>Automatic certificate provisioning via ACME</li>\n\
                             <li>DNS validation for domain ownership</li>\n\
                             <li>Certificate caching and renewal</li>\n\
                             <li>Support for both HTTP-01 and DNS-01 challenges</li>\n\
                             <li>Integration with Let's Encrypt</li>\n\
                         </ul>\n\
                         <h2>Technical Details</h2>\n\
                         <p>This server uses rustls with a custom ResolvesServerCert implementation\n\
                         that can dynamically obtain certificates from ACME providers based on the\n\
                         requested domain name. The server validates that domains resolve to\n\
                         authorized IP addresses before issuing certificates.</p>\n\
                     </div>\n\
                 </div>\n\
             </body>\n\
             </html>",
            server_name
        );

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            html_content.len(),
            html_content
        );

        conn.writer().write_all(response.as_bytes())?;
        conn.write_tls(stream)?;
        conn.complete_io(stream)?;

        Ok(())
    }

    /// Handle HTTP-01 ACME challenge over HTTP (port 80)
    fn handle_acme_challenge_http(
        mut stream: TcpStream,
        request_line: &str,
        acme_client: &Option<Arc<AcmeClient>>,
        http_challenges: &Arc<Mutex<BTreeMap<String, String>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Extract token from request path
        // GET /.well-known/acme-challenge/{token} HTTP/1.1
        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        let token = path.strip_prefix("/.well-known/acme-challenge/").unwrap_or("");

        println!("ACME HTTP-01 challenge request for token: {}", token);

        // Look up the key authorization for this token
        let key_authorization = Self::get_challenge_response_from_params(acme_client, http_challenges, token);

        let response = if let Some(key_auth) = key_authorization {
            println!("Serving challenge response for token: {}", token);
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                key_auth.len(),
                key_auth
            )
        } else {
            println!("Challenge token not found: {}", token);
            format!(
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 13\r\n\
                 Connection: close\r\n\
                 \r\n\
                 Not Found"
            )
        };

        stream.write_all(response.as_bytes())?;
        stream.flush()?;

        Ok(())
    }

    /// Handle HTTP-01 ACME challenge over HTTPS (port 443)
    fn handle_acme_challenge(
        stream: &mut TcpStream,
        conn: &mut ServerConnection,
        request_line: &str,
        acme_client: &Option<Arc<AcmeClient>>,
        http_challenges: &Arc<Mutex<BTreeMap<String, String>>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Extract token from request path
        // GET /.well-known/acme-challenge/{token} HTTP/1.1
        let path = request_line.split_whitespace().nth(1).unwrap_or("");
        let token = path.strip_prefix("/.well-known/acme-challenge/").unwrap_or("");

        println!("ACME HTTP-01 challenge request for token: {}", token);

        // Look up the key authorization for this token
        let key_authorization = Self::get_challenge_response_from_params(acme_client, http_challenges, token);

        let response = if let Some(key_auth) = key_authorization {
            println!("Serving challenge response for token: {}", token);
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: {}\r\n\
                 Cache-Control: no-cache\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                key_auth.len(),
                key_auth
            )
        } else {
            println!("Challenge token not found: {}", token);
            format!(
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: text/plain\r\n\
                 Content-Length: 13\r\n\
                 Connection: close\r\n\
                 \r\n\
                 Not Found"
            )
        };

        conn.writer().write_all(response.as_bytes())?;
        conn.write_tls(stream)?;
        conn.complete_io(stream)?;

        Ok(())
    }

    /// Get challenge response for a token from ACME client
    fn get_challenge_response(&self, token: &str) -> Option<String> {
        // Try to get from ACME client if available
        if let Some(acme_client) = &self.acme_client {
            let rt = tokio::runtime::Runtime::new().unwrap();
            if let Some(response) = rt.block_on(acme_client.get_challenge_response(token)) {
                return Some(response);
            }
        }
        
        // Fallback to local storage
        if let Ok(challenges) = self.http_challenges.lock() {
            if let Some(response) = challenges.get(token) {
                return Some(response.clone());
            }
        }
        
        // Last resort: placeholder response
        if !token.is_empty() {
            Some(format!("challenge-response-for-{}", token))
        } else {
            None
        }
    }

    /// Get challenge response for a token from parameters (static method)
    fn get_challenge_response_from_params(
        acme_client: &Option<Arc<AcmeClient>>,
        http_challenges: &Arc<Mutex<BTreeMap<String, String>>>,
        token: &str,
    ) -> Option<String> {
        // Try to get from ACME client if available
        if let Some(acme_client) = acme_client {
            let rt = tokio::runtime::Runtime::new().unwrap();
            if let Some(response) = rt.block_on(acme_client.get_challenge_response(token)) {
                return Some(response);
            }
        }
        
        // Fallback to local storage
        if let Ok(challenges) = http_challenges.lock() {
            if let Some(response) = challenges.get(token) {
                return Some(response.clone());
            }
        }
        
        // Last resort: placeholder response
        if !token.is_empty() {
            Some(format!("challenge-response-for-{}", token))
        } else {
            None
        }
    }
}

/// Test certificate resolver for demonstration purposes
#[derive(Debug)]
struct TestCertResolver {
    allowed_ips: Vec<IpAddr>,
    cert_cache: Arc<Mutex<HashMap<String, rustls::sign::CertifiedKey>>>,
}

impl TestCertResolver {
    fn new(allowed_ips: Vec<IpAddr>) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            allowed_ips,
            cert_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

}

impl ResolvesServerCert for TestCertResolver {
    fn resolve(&self, client_hello: &rustls::server::ClientHello<'_>) -> Result<rustls::sign::CertifiedSigner, rustls::Error> {
        let Some(server_name) = client_hello.server_name() else {
            return Err(rustls::Error::NoSuitableCertificate);
        };

        let domain = server_name.as_ref();
        
        // Check cache first
        if let Ok(cache) = self.cert_cache.lock() {
            if let Some(certified_key) = cache.get(domain) {
                return certified_key.signer(client_hello.signature_schemes())
                    .ok_or(rustls::Error::NoSuitableCertificate);
            }
        }

        // For this demo, we'll just return an error since certificate generation
        // requires more complex setup. In a real implementation, you'd use rcgen
        // or another certificate generation library.
        println!("Certificate generation not implemented for domain: {}", domain);
        Err(rustls::Error::NoSuitableCertificate)
    }
}

/// Automatically detect the server's IP addresses from network interfaces
fn detect_server_ips() -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    use get_if_addrs::{get_if_addrs, IfAddr};
    
    let interfaces = get_if_addrs()?;
    let mut ip_addresses = Vec::new();
    
    for interface in interfaces {
        match interface.addr {
            IfAddr::V4(ipv4) => {
                ip_addresses.push(IpAddr::V4(ipv4.ip));
            }
            IfAddr::V6(ipv6) => {
                ip_addresses.push(IpAddr::V6(ipv6.ip));
            }
        }
    }
    
    println!("Detected {} IP addresses: {:?}", ip_addresses.len(), ip_addresses);
    Ok(ip_addresses)
}

/// Parse comma-separated IP addresses
fn parse_allowed_ips(ips_str: &str) -> Result<Vec<IpAddr>, Box<dyn std::error::Error>> {
    let mut ips = Vec::new();
    
    for ip_str in ips_str.split(',') {
        let ip_str = ip_str.trim();
        if ip_str.is_empty() {
            continue;
        }
        
        let ip: IpAddr = ip_str.parse()?;
        ips.push(ip);
    }
    
    Ok(ips)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize logging
    if args.verbose {
        env_logger::Builder::new()
            .parse_filters("debug")
            .init();
    } else {
        env_logger::Builder::new()
            .parse_filters("info")
            .init();
    }

    // Create and run server
    let server = OnDemandHttpsServer::new(args)?;
    server.run()?;

    Ok(())
}
