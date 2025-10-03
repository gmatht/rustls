// comment.expand.rs - HTML form generator for comment system
use std::collections::HashMap;

/// Generate HTML form for comment submission
pub fn extend(url: &str, args: &str) -> String {
    // Parse any arguments (currently not used, but available for future expansion)
    let _parsed_args = parse_args(args);
    
    // Extract the current page URL for the form action
    let form_action = if url.contains('?') {
        // If URL has query parameters, strip them for the form action
        url.split('?').next().unwrap_or(url)
    } else {
        url
    };
    
    // Get canonical path for MD5 calculation
    let canonical_path = if let Some((path, _)) = form_action.split_once('?') {
        if let Some((path, _)) = path.split_once('#') {
            path
        } else {
            path
        }
    } else if let Some((path, _)) = form_action.split_once('#') {
        path
    } else {
        form_action
    };
    
    // Calculate MD5 hash of canonical path
    let md5_hash = calculate_md5(canonical_path);
    
    // Load and display live comments
    let live_comments_html = load_live_comments(&md5_hash);
    
    // Generate the comment form HTML
    format!(r#"
    {}
    <div class="comment-form" style="margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; background-color: #f9f9f9;">
    <h3>Leave a Comment</h3>
    <form action="/cgi-bin/comment" method="GET" style="display: flex; flex-direction: column; gap: 10px;">
        <input type="hidden" name="return_url" value="{}">
        
        <div style="display: flex; flex-direction: column;">
            <label for="comment_user" style="font-weight: bold; margin-bottom: 5px;">Pseudonym - how you want to be described on this site:</label>
            <input type="text" id="comment_user" name="USER" required 
                   style="padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px;"
                   placeholder="Enter your pseudonym">
        </div>
        
        <div style="display: flex; flex-direction: column;">
            <label for="comment_text" style="font-weight: bold; margin-bottom: 5px;">Your Comment:</label>
            <textarea id="comment_text" name="TEXT" required rows="4" 
                      style="padding: 8px; border: 1px solid #ccc; border-radius: 3px; font-size: 14px; resize: vertical;"
                      placeholder="Enter your comment here..."></textarea>
        </div>
        
        <div style="display: flex; gap: 10px; margin-top: 10px;">
            <button type="submit" 
                    style="background-color: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; font-size: 14px;"
                    onmouseover="this.style.backgroundColor='#005a87'" 
                    onmouseout="this.style.backgroundColor='#007cba'">
                Submit Comment
            </button>
            <button type="button" onclick="clearForm()" 
                    style="background-color: #6c757d; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; font-size: 14px;"
                    onmouseover="this.style.backgroundColor='#545b62'" 
                    onmouseout="this.style.backgroundColor='#6c757d'">
                Clear
            </button>
        </div>
    </form>
    
    <style>
        /* Dark mode support for comment forms */
        @media (prefers-color-scheme: dark) {{
            .comment-form {{
                background-color: #2d2d2d !important;
                border-color: #555 !important;
                color: #e0e0e0 !important;
            }}
            
            .comment-form h3 {{
                color: #ffffff !important;
            }}
            
            .comment-form label {{
                color: #e0e0e0 !important;
            }}
            
            .comment-form input[type="text"],
            .comment-form textarea {{
                background-color: #3d3d3d !important;
                border-color: #666 !important;
                color: #ffffff !important;
            }}
            
            .comment-form input[type="text"]::placeholder,
            .comment-form textarea::placeholder {{
                color: #999 !important;
            }}
            
            .comment-form input[type="text"]:focus,
            .comment-form textarea:focus {{
                border-color: #007cba !important;
                outline: none !important;
                box-shadow: 0 0 0 2px rgba(0, 124, 186, 0.2) !important;
            }}
            
            .live-comments {{
                background-color: #2d2d2d !important;
                border-color: #555 !important;
                color: #e0e0e0 !important;
            }}
            
            .live-comments h3 {{
                color: #ffffff !important;
            }}
            
            .live-comments .comment {{
                background-color: #3d3d3d !important;
                border-left-color: #007cba !important;
            }}
            
            .live-comments .comment-author {{
                color: #ffffff !important;
            }}
            
            .live-comments .comment-text {{
                color: #e0e0e0 !important;
            }}
        }}
        
        /* Force light mode for comment forms if needed */
        .comment-form.force-light {{
            background-color: #f9f9f9 !important;
            border-color: #ddd !important;
            color: #333 !important;
        }}
        
        .comment-form.force-light h3 {{
            color: #333 !important;
        }}
        
        .comment-form.force-light label {{
            color: #333 !important;
        }}
        
        .comment-form.force-light input[type="text"],
        .comment-form.force-light textarea {{
            background-color: #ffffff !important;
            border-color: #ccc !important;
            color: #333 !important;
        }}
        
        .comment-form.force-light input[type="text"]::placeholder,
        .comment-form.force-light textarea::placeholder {{
            color: #666 !important;
        }}
        
        /* JavaScript-controlled dark mode class */
        .comment-form.dark-mode {{
            background-color: #2d2d2d !important;
            border-color: #555 !important;
            color: #e0e0e0 !important;
        }}
        
        .comment-form.dark-mode h3 {{
            color: #ffffff !important;
        }}
        
        .comment-form.dark-mode label {{
            color: #e0e0e0 !important;
        }}
        
        .comment-form.dark-mode input[type="text"],
        .comment-form.dark-mode textarea {{
            background-color: #3d3d3d !important;
            border-color: #666 !important;
            color: #ffffff !important;
        }}
        
        .comment-form.dark-mode input[type="text"]::placeholder,
        .comment-form.dark-mode textarea::placeholder {{
            color: #999 !important;
        }}
        
        .comment-form.dark-mode input[type="text"]:focus,
        .comment-form.dark-mode textarea:focus {{
            border-color: #007cba !important;
            outline: none !important;
            box-shadow: 0 0 0 2px rgba(0, 124, 186, 0.2) !important;
        }}
        
        .live-comments.dark-mode {{
            background-color: #2d2d2d !important;
            border-color: #555 !important;
            color: #e0e0e0 !important;
        }}
        
        .live-comments.dark-mode h3 {{
            color: #ffffff !important;
        }}
        
        .live-comments.dark-mode .comment {{
            background-color: #3d3d3d !important;
            border-left-color: #007cba !important;
        }}
        
        .live-comments.dark-mode .comment-author {{
            color: #ffffff !important;
        }}
        
        .live-comments.dark-mode .comment-text {{
            color: #e0e0e0 !important;
        }}
    </style>
    
    <script>
        function clearForm() {{
            document.getElementById('comment_user').value = '';
            document.getElementById('comment_text').value = '';
        }}
        
        // Enhanced dark mode detection and handling
        function detectDarkMode() {{
            // Check for Hugo's dark mode class
            const isHugoDark = document.documentElement.classList.contains('dark') || 
                              document.body.classList.contains('dark') ||
                              document.querySelector('html[data-theme="dark"]') !== null;
            
            // Check for system preference
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            
            return isHugoDark || prefersDark;
        }}
        
        function applyDarkMode() {{
            const commentForm = document.querySelector('.comment-form');
            const liveComments = document.querySelector('.live-comments');
            const isDark = detectDarkMode();
            
            if (commentForm) {{
                if (isDark) {{
                    commentForm.classList.add('dark-mode');
                }} else {{
                    commentForm.classList.remove('dark-mode');
                }}
            }}
            
            if (liveComments) {{
                if (isDark) {{
                    liveComments.classList.add('dark-mode');
                }} else {{
                    liveComments.classList.remove('dark-mode');
                }}
            }}
        }}
        
        // Add some basic form validation
        document.addEventListener('DOMContentLoaded', function() {{
            const form = document.querySelector('form[action="/cgi-bin/comment"]');
            if (form) {{
                form.addEventListener('submit', function(e) {{
                    const user = document.getElementById('comment_user').value.trim();
                    const text = document.getElementById('comment_text').value.trim();
                    
                    if (!user || !text) {{
                        e.preventDefault();
                        alert('Please fill in both your pseudonym and comment.');
                        return false;
                    }}
                    
                    if (user.length < 2) {{
                        e.preventDefault();
                        alert('Please enter a valid pseudonym (at least 2 characters).');
                        return false;
                    }}
                    
                    if (text.length < 10) {{
                        e.preventDefault();
                        alert('Please enter a more detailed comment (at least 10 characters).');
                        return false;
                    }}
                }});
            }}
            
            // Apply dark mode styling on page load
            applyDarkMode();
            
            // Listen for theme changes (useful for Hugo themes with dynamic switching)
            const observer = new MutationObserver(function(mutations) {{
                mutations.forEach(function(mutation) {{
                    if (mutation.type === 'attributes' && 
                        (mutation.attributeName === 'class' || mutation.attributeName === 'data-theme')) {{
                        applyDarkMode();
                    }}
                }});
            }});
            
            observer.observe(document.documentElement, {{
                attributes: true,
                attributeFilter: ['class', 'data-theme']
            }});
            
            // Listen for system theme changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', applyDarkMode);
        }});
    </script>
</div>
"#, live_comments_html, form_action)
}

/// Calculate MD5 hash of a string
fn calculate_md5(input: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    let hash = hasher.finish();
    
    format!("{:x}", hash)
}

/// Load live comments for a specific MD5 hash
fn load_live_comments(md5_hash: &str) -> String {
    use std::fs;
    use std::path::Path;
    
    let live_file = Path::new("/var/spool/easypeas/comments/live").join(md5_hash);
    
    if !live_file.exists() {
        return String::new();
    }
    
    match fs::read_to_string(&live_file) {
        Ok(content) => {
            let comments: Vec<&str> = content.lines().filter(|line| !line.trim().is_empty()).collect();
            
            if comments.is_empty() {
                return String::new();
            }
            
            let mut html = String::new();
            html.push_str(r#"<div class="live-comments" style="margin: 20px 0; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px; background-color: #f8f9fa;">"#);
            html.push_str("<h3>Comments</h3>");
            
            for comment in comments {
                if let Some(parsed_comment) = parse_comment(comment) {
                    html.push_str(&format!(
                        r#"<div class="comment" style="margin: 15px 0; padding: 15px; border-left: 3px solid #007cba; background-color: white; border-radius: 3px;">"#,
                    ));
                    html.push_str(&format!(
                        r#"<div class="comment-author" style="font-weight: bold; color: #333; margin-bottom: 8px;">{}</div>"#,
                        html_escape(&parsed_comment.name)
                    ));
                    html.push_str(&format!(
                        r#"<div class="comment-text" style="color: #555; line-height: 1.5;">{}</div>"#,
                        html_escape(&parsed_comment.text)
                    ));
                    html.push_str("</div>");
                }
            }
            
            html.push_str("</div>");
            html
        }
        Err(_) => String::new(),
    }
}

/// Parse a comment string into structured data
fn parse_comment(comment: &str) -> Option<ParsedComment> {
    // Comment format: "return_url=URL&USER=NAME&TEXT=COMMENT" (prefix already removed)
    
    let params: std::collections::HashMap<&str, &str> = comment
        .split('&')
        .filter_map(|pair| {
            if let Some((key, value)) = pair.split_once('=') {
                Some((key, value))
            } else {
                None
            }
        })
        .collect();
    
    // URL decode the USER and TEXT parameters
    let name = url_decode(params.get("USER")?).ok()?.to_string();
    let text = url_decode(params.get("TEXT")?).ok()?.to_string();
    
    Some(ParsedComment { name, text })
}

/// Structure for parsed comment data
struct ParsedComment {
    name: String,
    text: String,
}

/// URL decode function
fn url_decode(s: &str) -> Result<String, String> {
    let mut result = String::new();
    let mut chars = s.chars();
    
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex1 = chars.next().ok_or("Invalid URL encoding")?;
            let hex2 = chars.next().ok_or("Invalid URL encoding")?;
            
            let hex_str = format!("{}{}", hex1, hex2);
            let byte = u8::from_str_radix(&hex_str, 16)
                .map_err(|_| "Invalid hex in URL encoding")?;
            
            result.push(byte as char);
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    
    Ok(result)
}

/// HTML escape function
fn html_escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '&' => "&amp;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#x27;".to_string(),
            _ => c.to_string(),
        })
        .collect()
}

/// Parse arguments (currently not used but available for future expansion)
fn parse_args(args: &str) -> HashMap<String, String> {
    let mut parsed = HashMap::new();
    
    // Simple argument parsing - could be extended for more complex options
    if !args.is_empty() {
        // For now, just store the raw args
        parsed.insert("raw_args".to_string(), args.to_string());
    }
    
    parsed
}

/// Example usage and testing
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_comment_form_generation() {
        let result = extend("https://example.com/page", "");
        assert!(result.contains("Leave a Comment"));
        assert!(result.contains("action=\"/cgi-bin/comment\""));
        assert!(result.contains("name=\"USER\""));
        assert!(result.contains("name=\"TEXT\""));
    }

    #[test]
    fn test_form_with_query_params() {
        let result = extend("https://example.com/page?param=value", "");
        assert!(result.contains("action=\"/cgi-bin/comment\""));
    }

    #[test]
    fn test_url_decode() {
        assert_eq!(url_decode("Hello%20World").unwrap(), "Hello World");
        assert_eq!(url_decode("Test%3Cscript%3E").unwrap(), "Test<script>");
        assert_eq!(url_decode("A%26B").unwrap(), "A&B");
        assert_eq!(url_decode("Hello+World").unwrap(), "Hello World");
    }

    #[test]
    fn test_parse_comment_with_encoding() {
        let comment = "return_url=test&USER=John%20Doe&TEXT=This%20is%20a%20test%20%3Cscript%3E";
        let parsed = parse_comment(comment);
        assert!(parsed.is_some());
        let parsed = parsed.unwrap();
        assert_eq!(parsed.name, "John Doe");
        assert_eq!(parsed.text, "This is a test <script>");
    }
}
