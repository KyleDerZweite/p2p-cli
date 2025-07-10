/// Security levels available in the application
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    Quick = 0,     // Current behavior - no identity verification
    Tofu = 1,      // Trust on first use - verify peer identity
    Secure = 2,    // Signatures + key rotation
    Maximum = 3,   // No persistent history
}

impl SecurityLevel {
    /// Parse security level from a string or number
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "0" | "quick" => Ok(SecurityLevel::Quick),
            "1" | "tofu" => Ok(SecurityLevel::Tofu),
            "2" | "secure" => Ok(SecurityLevel::Secure),
            "3" | "max" | "maximum" => Ok(SecurityLevel::Maximum),
            _ => Err(format!("Invalid security level: {}. Use 0-3 or quick/tofu/secure/max", s)),
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
            SecurityLevel::Quick => "Quick & dirty - no identity verification (current behavior)",
            SecurityLevel::Tofu => "Trust on first use - verify peer identity",
            SecurityLevel::Secure => "Secure communications - signatures + key rotation",
            SecurityLevel::Maximum => "Maximum security - no persistent history",
        }
    }

    /// Check if this security level requires identity verification
    pub fn requires_identity(&self) -> bool {
        match self {
            SecurityLevel::Quick => false,
            SecurityLevel::Tofu | SecurityLevel::Secure | SecurityLevel::Maximum => true,
        }
    }

    /// Check if this security level requires digital signatures
    pub fn requires_signatures(&self) -> bool {
        match self {
            SecurityLevel::Quick | SecurityLevel::Tofu => false,
            SecurityLevel::Secure | SecurityLevel::Maximum => true,
        }
    }

    /// Check if this security level requires key rotation
    pub fn requires_key_rotation(&self) -> bool {
        match self {
            SecurityLevel::Quick | SecurityLevel::Tofu => false,
            SecurityLevel::Secure | SecurityLevel::Maximum => true,
        }
    }

    /// Check if this security level disables persistent history
    pub fn disable_persistent_history(&self) -> bool {
        match self {
            SecurityLevel::Quick | SecurityLevel::Tofu | SecurityLevel::Secure => false,
            SecurityLevel::Maximum => true,
        }
    }

    /// Negotiate security level with peer (use the higher level)
    pub fn negotiate_with(self, peer_level: SecurityLevel) -> SecurityLevel {
        match (self as u8).max(peer_level as u8) {
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