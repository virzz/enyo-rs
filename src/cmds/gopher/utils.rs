//! Gopher utility functions

/// URL escape and replace special characters for FastCGI payload
pub fn replace_fastcgi_payload(p: &str) -> String {
    p.replace('+', "%20").replace("%2F", "/")
}

/// URL escape and replace special characters for Redis payload
pub fn replace_redis_payload(p: &str) -> String {
    let p = replace_fastcgi_payload(p);
    p.replace("%25", "%").replace("%3A", ":")
}

/// Apply URL encoding multiple times
pub fn query_escape(s: &str, count: usize) -> String {
    let mut result = s.to_string();
    for _ in 0..count {
        result = urlencoding::encode(&result).into_owned();
    }
    result
}

