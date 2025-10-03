// Example extension for processing #EXTEND:example(...) directives

pub fn extend(_url: &str, args: &str) -> String {
    // Parse arguments (simple comma-separated for this example)
    let parsed_args: Vec<&str> = args.split(',').map(|s| s.trim()).collect();
    
    match parsed_args.as_slice() {
        ["greeting", name] => {
            format!("<div class=\"greeting\">Hello, {}!</div>", name)
        }
        ["time"] => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            format!("<div class=\"timestamp\">Current time: {}</div>", now)
        }
        ["include", filename] => {
            format!("<div class=\"include\">Including: {}</div>", filename)
        }
        _ => {
            format!("<div class=\"error\">Unknown example extension: {}</div>", args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greeting() {
        assert_eq!(
            extend("", "greeting, World"),
            "<div class=\"greeting\">Hello, World!</div>"
        );
    }

    #[test]
    fn test_time() {
        let result = extend("", "time");
        assert!(result.contains("Current time:"));
    }

    #[test]
    fn test_unknown() {
        assert_eq!(
            extend("", "unknown, args"),
            "<div class=\"error\">Unknown example extension: unknown, args</div>"
        );
    }
}
