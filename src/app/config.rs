/// Security levels available in the application
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    Quick = 0,   // Encrypted and signed, explicit approval each session
    Tofu = 1,    // Persistently pin peer identities
    Secure = 2,  // Fresh forward-secret channel for every application message
    Maximum = 3, // Secure plus memory-only history/trust state
}

impl SecurityLevel {
    /// Parse security level from a string or number
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "0" | "quick" => Ok(SecurityLevel::Quick),
            "1" | "tofu" => Ok(SecurityLevel::Tofu),
            "2" | "secure" => Ok(SecurityLevel::Secure),
            "3" | "max" | "maximum" => Ok(SecurityLevel::Maximum),
            _ => Err(format!(
                "Invalid security level: {}. Use 0-3 or quick/tofu/secure/max",
                s
            )),
        }
    }

    /// Get display name for UI
    pub fn display_name(&self) -> &'static str {
        match self {
            SecurityLevel::Quick => "QUICK MODE",
            SecurityLevel::Tofu => "TOFU MODE",
            SecurityLevel::Secure => "SECURE MODE",
            SecurityLevel::Maximum => "MAX SECURITY",
        }
    }

    /// Get description of security level
    pub fn description(&self) -> &'static str {
        match self {
            SecurityLevel::Quick => "Encrypted + signed transport; approve peers each session",
            SecurityLevel::Tofu => "Encrypted + signed transport with persistent identity pinning",
            SecurityLevel::Secure => "TOFU plus a fresh forward-secret Noise channel per message",
            SecurityLevel::Maximum => "Secure transport with memory-only history and trust state",
        }
    }

    /// Check if this security level requires identity verification
    pub fn requires_identity(&self) -> bool {
        match self {
            SecurityLevel::Quick
            | SecurityLevel::Tofu
            | SecurityLevel::Secure
            | SecurityLevel::Maximum => true,
        }
    }

    /// Check if this security level requires digital signatures
    pub fn requires_signatures(&self) -> bool {
        true
    }

    /// Check if this security level requires key rotation
    pub fn requires_key_rotation(&self) -> bool {
        true
    }

    /// Check if this security level disables persistent history
    pub fn disable_persistent_history(&self) -> bool {
        match self {
            SecurityLevel::Quick | SecurityLevel::Tofu | SecurityLevel::Secure => false,
            SecurityLevel::Maximum => true,
        }
    }

    /// Report the effective shared policy conservatively: a session is only as
    /// strong as the weaker endpoint's declared policy.
    pub fn negotiate_with(self, peer_level: SecurityLevel) -> SecurityLevel {
        match (self as u8).min(peer_level as u8) {
            0 => SecurityLevel::Quick,
            1 => SecurityLevel::Tofu,
            2 => SecurityLevel::Secure,
            3 => SecurityLevel::Maximum,
            _ => SecurityLevel::Quick,
        }
    }
}

impl From<u8> for SecurityLevel {
    fn from(value: u8) -> Self {
        match value {
            1 => SecurityLevel::Tofu,
            2 => SecurityLevel::Secure,
            3 => SecurityLevel::Maximum,
            _ => SecurityLevel::Quick, // Default
        }
    }
}

impl std::fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub port: u16,
    pub security_level: SecurityLevel,
}

impl AppConfig {
    /// Create new application configuration
    pub fn new(port: u16, security_level: SecurityLevel) -> Self {
        Self {
            port,
            security_level,
        }
    }

    /// Create default configuration
    pub fn default() -> Self {
        Self {
            port: 8080,
            security_level: SecurityLevel::Quick,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.port == 0 {
            return Err("Port cannot be 0".to_string());
        }

        if self.port < 1024 {
            eprintln!("Warning: Using port {} requires root privileges", self.port);
        }

        Ok(())
    }
}
