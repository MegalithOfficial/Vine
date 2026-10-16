pub struct Sanitizer;

impl Sanitizer {
    /// Validates Minecraft username according to Mojang specifications:
    /// - Length: between 2 and 16 characters
    /// - Characters: ASCII alphanumeric (a-z, A-Z, 0-9) and underscore (_)
    pub fn is_valid_username(name: &str) -> bool {
        let len = name.len();
        if !(2..=16).contains(&len) {
            return false;
        }

        name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    }

    /// Sanitizes virtual host string:
    /// - Strips null bytes (`\0`) which could break BungeeCord packet format
    /// - Truncates to max 255 characters
    /// - Strips control characters
    pub fn sanitize_host(host: &str) -> String {
        // Forge appends "\0FML\0" markers and a forged "\0ip\0uuid" would spoof BungeeCord forwarding
        let host = host.split('\0').next().unwrap_or_default();
        let mut clean = String::with_capacity(host.len().min(255));
        for ch in host.chars() {
            if clean.len() >= 255 {
                break;
            }
            if !ch.is_control() {
                clean.push(ch);
            }
        }
        clean
    }

    /// Validates packet size against maximum limit
    pub fn is_valid_packet_size(size: usize, max_allowed: usize) -> bool {
        size <= max_allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_validation() {
        assert!(Sanitizer::is_valid_username("Alex"));
        assert!(Sanitizer::is_valid_username("Steve_99"));
        assert!(Sanitizer::is_valid_username("a_"));

        assert!(!Sanitizer::is_valid_username(""));
        assert!(!Sanitizer::is_valid_username("a"));
        assert!(!Sanitizer::is_valid_username("A_very_long_username_here"));
        assert!(!Sanitizer::is_valid_username("Player!@#"));
        assert!(!Sanitizer::is_valid_username("Player with space"));
        assert!(!Sanitizer::is_valid_username("Player\0Null"));
    }

    #[test]
    fn test_host_sanitizer() {
        assert_eq!(Sanitizer::sanitize_host("mc.example.com"), "mc.example.com");
        assert_eq!(
            Sanitizer::sanitize_host("mc.example.com\0malicious_ip\0uuid"),
            "mc.example.com"
        );
        assert_eq!(
            Sanitizer::sanitize_host("mc.example.com\0FML3\0"),
            "mc.example.com"
        );
    }
}
