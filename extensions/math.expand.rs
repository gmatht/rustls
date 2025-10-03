// Math extension for processing #EXTEND:math(...) directives

pub fn extend(_url: &str, args: &str) -> String {
    // Parse arguments for math operations
    let parts: Vec<&str> = args.split(',').map(|s| s.trim()).collect();
    
    match parts.as_slice() {
        ["add", a, b] => {
            if let (Ok(num_a), Ok(num_b)) = (a.parse::<f64>(), b.parse::<f64>()) {
                let result = num_a + num_b;
                format!("<span class=\"math-result\">{} + {} = {}</span>", a, b, result)
            } else {
                format!("<span class=\"math-error\">Invalid numbers: {}, {}</span>", a, b)
            }
        }
        ["multiply", a, b] => {
            if let (Ok(num_a), Ok(num_b)) = (a.parse::<f64>(), b.parse::<f64>()) {
                let result = num_a * num_b;
                format!("<span class=\"math-result\">{} × {} = {}</span>", a, b, result)
            } else {
                format!("<span class=\"math-error\">Invalid numbers: {}, {}</span>", a, b)
            }
        }
        ["pi"] => {
            format!("<span class=\"math-constant\">π = 3.14159265359</span>")
        }
        _ => {
            format!("<span class=\"math-error\">Unknown math operation: {}</span>", args)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(
            extend("", "add, 5, 3"),
            "<span class=\"math-result\">5 + 3 = 8</span>"
        );
    }

    #[test]
    fn test_multiply() {
        assert_eq!(
            extend("", "multiply, 4, 7"),
            "<span class=\"math-result\">4 × 7 = 28</span>"
        );
    }

    #[test]
    fn test_pi() {
        let result = extend("", "pi");
        assert!(result.contains("π = 3.14159265359"));
    }
}
