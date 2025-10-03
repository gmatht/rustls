// comment.bin.rs - CGI-like comment handler
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

// Import CgiEnv and url_decode from the main crate
use crate::cgi_env::{CgiEnv, url_decode};

pub fn calculate_md5(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

/// Main CGI function for comment handling
pub fn cgi_main(env: &CgiEnv) -> Result<String, String> {
    // Parse query parameters
    let params = env.parse_query();
    
    // Get return URL from query parameters
    let return_url = params.get("return_url")
        .map(|s| url_decode(s))
        .unwrap_or_else(|| "/".to_string());
    
    // Create the comment entry
    let comment_entry = format!(
        "{}\n",
        env.request_uri
    );
    // Limit text to 10K characters
    if comment_entry.len() > 10000 {
        return Ok(format!(  
            "Content-Type: text/html\r\n\r\n\
            <!DOCTYPE html>\n\
            <html>\n\
            <head><title>Comment Too Long</title></head>\n\
            <body>\n\
            <h1>Comment Too Long</h1>\n\
            <p>The comment is too long and was not submitted.</p>\n\
            <p><a href=\"{}\">Go back</a></p>\n\
            </body>\n\
            </html>",
            return_url
        ));
    }
    
    // Ensure the comments directory exists
    let comments_dir = Path::new("/var/spool/easypeas/comments");
    if !comments_dir.exists() {
        std::fs::create_dir_all(comments_dir)
            .map_err(|e| format!("Failed to create comments directory: {}", e))?;
    }
    
    // Check for duplicate comment using MD5 hashes
    let comments_file = comments_dir.join("in");
    static EXISTING_HASHES: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    let new_comment_hash = calculate_md5(&comment_entry);
    
    if EXISTING_HASHES.lock().unwrap().contains(&new_comment_hash) {
        return Ok(format!(
            "Content-Type: text/html\r\n\r\n\
            <!DOCTYPE html>\n\
            <html>\n\
            <head><title>Duplicate Comment</title></head>\n\
            <body>\n\
            <h1>Duplicate Comment Detected</h1>\n\
            <p>This comment is identical to a recent one and was not submitted.</p>\n\
            <p><a href=\"{}\">Go back</a></p>\n\
            </body>\n\
            </html>",
            return_url
        ));
    }
    
    
    // Append to the comments file
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&comments_file)
        .map_err(|e| format!("Failed to open comments file: {}", e))?;
    
    file.write_all(comment_entry.as_bytes())
        .map_err(|e| format!("Failed to write comment: {}", e))?;
    
    EXISTING_HASHES.lock().unwrap().insert(new_comment_hash);
    // Return success response
    Ok(format!(
        "Content-Type: text/html\r\n\r\n\
        <!DOCTYPE html>\n\
        <html>\n\
        <head><title>Comment Submitted</title></head>\n\
        <body>\n\
        <h1>Comment Submitted Successfully</h1>\n\
        <p>Your comment has been recorded.</p>\n\
        <p><a href=\"{}\">Go back</a></p>\n\
        </body>\n\
        </html>",
        return_url
    ))
}

/// Handler function that can be called from the main server
pub fn handle_comment_request(
    method: &str,
    uri: &str,
    host: &str,
    query_string: &str,
    headers: &HashMap<String, String>,
) -> Result<String, String> {
    let env = CgiEnv::from_request(method, uri, host, query_string, headers);
    cgi_main(&env)
}

