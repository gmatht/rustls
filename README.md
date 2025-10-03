# EasyPeas HTTPS Server

| ![Logo](logo.png) | I gave up trying to configure off-the-shelf webservers and decided it would be easier to just write my own that just automatically configured itself. This prototype should just work, provided you have already set up Lets Encrypt. <br><br>It supports extensions written in Rust, and comes with some default examples. Just add/remove extension `.rs` files to/from `extensions/` and run `cargo build --release` to get a single binary staticly linked with all your extensions. Then just run that binary on your server or run the `deploy.sh` script to set up systemd etc.<br> |
|:---:|:---|

At this point it should just work, and if it doesn't work on Linux it is a bug; however, no benchmarking has been done and only the most cursory security analysis.

*My favourite type of peas is HTT Ps*
## Features

- **ACME Integration**: Built-in Let's Encrypt certificate management (no certbot required!)
- **Automatic Domain Discovery**: Scans `/etc/letsencrypt/live/` for domains or uses ACME
- **Dual Protocol Support**: Serves both HTTP (port 80) and HTTPS (port 443)
- **Static File Serving**: Serves files from `/var/www/{domain}/` for each domain
   * Falls back to /var/www/html
- **Let's Encrypt Integration**: Uses fullchain.pem and privkey.pem certificates
- **HTTP-01 Challenge Support**: Handles ACME domain validation challenges
- **Automatic Certificate Renewal**: Background task for certificate management
- **Extension System**: Modular architecture with multiple extension types
- **Comment System**: Example extensions implementing commenting with moderation capabilities
- **Admin Panels**: Secure admin interfaces for content management
- **Privilege Dropping**: Drops to `www-data` after initialization for security
- **CGI-like Support**: Executes statically compile and linked CGI-like scripts for dynamic content
- **MIME Type Support**: Proper content types for common file formats
- **Comprehensive Logging**: Detailed request and error logging

## Requirements

- Rust 1.70+
- Let's Encrypt certificates in `/etc/letsencrypt/live/` (or use ACME mode)
- Document roots in `/var/www/{domain}/`
- Root privileges to bind to port 443

## Extension System

EasyPeas features a powerful modular extension system with four types of extensions:

### Extension Types

1. **`.expand.rs`** - Content expansion extensions that modify HTML content
2. **`.bin.rs`** - CGI-bin like extensions for dynamic content generation
3. **`.root.rs`** - Root-level extensions that run before privilege dropping
4. **`.admin.rs`** - Admin panel extensions for content management

Drop these files into `extensions/` at compile time to have you extensions linked into your single file webserver.

### Built-in Example Extensions

#### Comment System (`comment.*`)
- **`comment.expand.rs`**: Adds comment forms and displays live comments
- **`comment.bin.rs`**: Handles comment submission via CGI-like API
- **`comment.root.rs`**: Sets up comment directories and permissions
- **`comment.admin.rs`**: Provides comment moderation interface

#### Math Extension (`math.expand.rs`)
- Converts `#EXPAND:math(op,i,j)` blocks to rendered math, where op can be e.g. "add"

#### Example Extension (`example.expand.rs`)
- Demonstrates basic extension functionality
- Adds example content to pages

### Creating Custom Extensions

Extensions are automatically discovered by the build system. To create a new extension:

1. Add a `.rs` file to the `extensions/` directory with the appropriate suffix
2. Implement the required trait methods
3. The build system will automatically compile and register your extension

#### Example: Custom Expand Extension

```rust
// extensions/my_extension.expand.rs
use std::collections::HashMap;

pub fn extend(url: &str, args: &str) -> String {
    // Your extension logic here
    format!("<div>Custom content for {}</div>", url)
}
```

## Installation

1. Clone or download this project
2. Build the server:
   ```bash
   cargo build --release
   ```
3. Deploy using the included script:
   ```bash
   ./deploy.sh user@your-server.com
   ```

## Usage

### ACME Mode (Recommended)

1. Create document roots for your domains:
   ```bash
   sudo mkdir -p /var/www/example.com
   echo "<h1>Hello from example.com!</h1>" | sudo tee /var/www/example.com/index.html
   ```

2. Run the server with ACME certificate management:
   ```bash
   # Email defaults to webmaster@$HOSTNAME (if hostname contains a dot) or webmaster@domain (shortest domain from reverse DNS) or webmaster@localhost
   # Staging defaults to false (production Let's Encrypt)
   
   # Run with domain list
   sudo ./target/release/easypeas example.com another-domain.com
   ```

3. For testing, use the staging environment:
   ```bash
   export ACME_STAGING="true"
   sudo ./target/release/easypeas example.com another-domain.com
   ```

4. Customize the email address:
   ```bash
   export ACME_EMAIL="admin@example.com"
   sudo ./target/release/easypeas example.com another-domain.com
   ```

### Legacy Mode (Let's Encrypt Directory)

1. Ensure your Let's Encrypt certificates are in place:
   ```
   /etc/letsencrypt/live/example.com/fullchain.pem
   /etc/letsencrypt/live/example.com/privkey.pem
   ```

2. Create document roots for your domains:
   ```bash
   sudo mkdir -p /var/www/example.com
   echo "<h1>Hello from example.com!</h1>" | sudo tee /var/www/example.com/index.html
   ```

3. Run the server (requires root for port 443):
   ```bash
   sudo ./target/release/easypeas
   ```

   Or use the systemd service (if deployed):
   ```bash
   sudo systemctl start easypeas
   sudo systemctl enable easypeas  # Start on boot
   ```

4. Visit your domains:
   - http://example.com (HTTP on port 80)
   - https://example.com (HTTPS on port 443)
   - http://another-domain.com
   - https://another-domain.com

## Comment System

EasyPeas includes a complete commenting system with moderation capabilities:

### Features
- **Comment Forms**: Automatically replaces '#EXPAND:comment()' in served html files
- **Live Comments**: Accepted comments appear immediately on the page
- **Moderation**: Admin interface for approving/rejecting comments
- **Security**: Comments are sanitized and validated
- **Storage**: Comments stored in `/var/spool/easypeas/comments/`

### Admin Panel
- Access via secret URL: `https://your-domain.com/comment_{admin_key}`
- Admin key is generated automatically on first run and stored in /var/spool/easypeas.admin
- Batch moderation with checkboxes

## Admin System

EasyPeas provides secure admin panels for content management:

### Admin Key Management
- Keys are generated dynamically on first run
- Stored in `/var/spool/easypeas/admin`
- Keys are cached in memory for security
- Each extension gets its own unique admin key
- go to https://example.com/KEY to administer system.

### Security Features
- Admin keys are long, random alphanumeric strings
- Admin panels only accessible with correct keys
- Privilege dropping ensures admin operations run as `www-data`

## Configuration

### ACME Configuration

The server supports two modes of operation:

**ACME Mode (Default when domains are specified):**
- Automatically requests Let's Encrypt certificates for specified domains
- Handles HTTP-01 challenges for domain validation
- Stores certificates in `/var/lib/easypeas/certs/`
- Automatically renews certificates before expiration
- Uses staging environment by default (set `ACME_STAGING=false` for production)

**Legacy Mode (Fallback):**
- Scans `/etc/letsencrypt/live/` for existing domains
- Uses pre-existing certificates from certbot or other tools
- No automatic certificate management

### Environment Variables

- `ACME_EMAIL`: Email address for Let's Encrypt registration (defaults to `webmaster@$HOSTNAME` if hostname contains a dot, otherwise `webmaster@domain` where domain is the shortest domain found by reverse DNS, or `webmaster@localhost` as final fallback)
- `ACME_STAGING`: Set to "true" for staging Let's Encrypt environment (defaults to "false" for production)
- `ENABLE_DNS_DISCOVERY`: Enable automatic hostname discovery via DNS (defaults to "true")

### General Configuration

The server automatically:
- Serves files from `/var/www/{domain}/` for each domain
- Uses the first domain found as the default domain
- Maps file extensions to appropriate MIME types
- Handles ACME HTTP-01 challenges at `/.well-known/acme-challenge/`

## Supported File Types

- HTML: `.html`
- CSS: `.css`
- JavaScript: `.js`
- JSON: `.json`
- WASM: `.wasm`
- Images: `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.ico`
- Text: `.txt`
- Default: `application/octet-stream`

## Security Notes

- This is a basic implementation for development/testing
- In production, consider additional security measures
- Ensure proper file permissions on document roots
- Consider rate limiting and access controls

## Testing

The project includes test scripts for different platforms:
- `setup_example.sh`: Sets up example domains and content (Linux/macOS)
- `test_server.sh`: Creates test environment with self-signed certificates (Linux/macOS)
- `test_server.bat`: Windows batch script for test environment setup
- `test_server.ps1`: PowerShell script for test environment setup (Not sure that this would work on Windows though)

### Linux/macOS Testing
```bash
# Run the bash test script
chmod +x test_server.sh
./test_server.sh

#Test on a remote server
./remote_tesh.sh example.com

# Build and run the server
cargo build --release
sudo ./target/release/easypeas
```

## Deployment

### Automated Deployment

Use the included `deploy.sh` script for easy deployment:

```bash
./deploy.sh user@your-server.com
```

This script will:
1. Build the release binary
2. Copy it to the target server
3. Install it to `/usr/local/bin/easypeas`
4. Create and enable a systemd service
5. Set up proper security configurations

### Manual Deployment

1. Build the binary:
   ```bash
   cargo build --release
   ```

2. Copy to target server:
   ```bash
   scp target/release/easypeas user@server:/usr/local/bin/
   ```

3. Set permissions:
   ```bash
   ssh user@server "sudo chmod +x /usr/local/bin/easypeas"
   ```

4. Create systemd service (see `deploy.sh` for the service file)

### Systemd Service

The EasyPeas service includes:
- Automatic restart on failure
- Security hardening (NoNewPrivileges, PrivateTmp, etc.)
- Proper file system access controls
- Journal logging

Service management:
```bash
sudo systemctl start easypeas      # Start service
sudo systemctl stop easypeas       # Stop service
sudo systemctl restart easypeas    # Restart service
sudo systemctl status easypeas     # Check status
sudo journalctl -u easypeas -f     # View logs
```

## Performance Optimization

The project includes optimized build profiles:

- **Development**: Fast compilation with debug info
- **Test**: Balanced optimization for testing
- **Release**: Maximum optimization with LTO, size optimization, and stripped symbols

### Binary Sizes
- Debug build: ~62 MB
- Release build: ~4.9 MB

The release profile uses:
- `lto = "fat"`: Full Link Time Optimization
- `codegen-units = 1`: Single codegen unit for better optimization
- `opt-level = "z"`: Optimize for size
- `strip = true`: Remove debug symbols
- `panic = "abort"`: Smaller binary size

## File Structure

```
EasyPeas_HTTPS/
├── src/                    # Source code
│   ├── main.rs            # Main server implementation
│   └── cgi_env.rs         # CGI environment utilities
├── extensions/            # Extension modules
│   ├── comment.*.rs       # Comment system extensions
│   ├── math.expand.rs     # Math rendering extension
│   └── example.expand.rs  # Example extension
├── target/                # Build output
│   └── release/easypeas   # Compiled binary
├── deploy.sh              # Deployment script
├── Cargo.toml            # Rust project configuration
└── README.md             # This file
```

## Directory Structure (Server)

```
/var/www/{domain}/         # Document roots for each domain
/etc/letsencrypt/live/     # Let's Encrypt certificates
/var/spool/easypeas/       # EasyPeas data directory
├── admin                 # Admin keys file
└── comments/             # Comment system storage
    ├── in               # Incoming comments
    ├── processing       # Comments awaiting moderation
    ├── accept           # Accepted comments
    ├── reject           # Rejected comments
    └── live/             # Live comments by URL hash
```

## Troubleshooting

### Common Issues

1. **Permission Denied on Port 443**
   - Ensure running as root or with sudo
   - Check if another service is using port 443

2. **Certificate Not Found**
   - For ACME mode: Ensure domains are specified as command line arguments
   - For legacy mode: Verify certificates exist in `/etc/letsencrypt/live/{domain}/`
   - Check file permissions (should be readable by root)
   - Ensure ACME_EMAIL environment variable is set for ACME mode

3. **Admin Panel Not Accessible**
   - Check admin key in `/var/spool/easypeas/admin`
   - Verify URL format: `https://domain.com/extension_{key}`

4. **Comments Not Appearing**
   - Check comment moderation in admin panel
   - Verify `/var/spool/easypeas/comments/` directory permissions
   - Ensure `www-data` user has write access

5. **Extensions Not Loading**
   - Check build output for compilation errors
   - Verify extension files are in `extensions/` directory
   - Ensure proper trait implementations

6. **ACME Certificate Issues**
   - Verify domain is accessible from the internet
   - Check that port 80 is open for HTTP-01 challenges
   - Ensure ACME_EMAIL is set correctly
   - Use staging environment first (`ACME_STAGING=true`)
   - Check certificate directory permissions: `/var/lib/easypeas/certs/`

### Debugging

- Check server logs: `sudo journalctl -u easypeas -f`
- Verify file permissions: `ls -la /var/spool/easypeas/comments/`
- Test admin access: `curl -k https://domain.com/comment_{key}`
- Check certificate validity: `openssl x509 -in /etc/letsencrypt/live/domain/fullchain.pem -text -noout`

### LICENSE:

The easyp webserver is distributed under the GPLv3. 

The library this was forked from was licensed under

- Apache License version 2.0.
- MIT license.
- ISC license.

The GPLv3 is liberal enough for what most normal people would want to do with a webserver, including most commericial purposes.  If you want to distribute under a license other than GPLv3 feel free to drop me a line. Alternatively just use the permissively licensed upstream library at https://github.com/rustls/rustls

### TODO:
- Security Audit
- Supply security updates via some secure channel.
- Investigate feasibility of automatic free subdomain instead of self-signed cert fallback.
