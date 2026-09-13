use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

const PREFIX: &str = "p2p-cli:v1:";
const MAX_LENGTH: usize = 8192;

/// An out-of-band identity pin and direct routes. It contains no secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub identity_key: String,
    pub candidates: Vec<SocketAddr>,
}

impl Invitation {
    pub fn new(identity_key: String, candidates: Vec<SocketAddr>) -> Result<Self, String> {
        let invitation = Self {
            identity_key,
            candidates,
        };
        invitation.validate()?;
        Ok(invitation)
    }

    fn validate(&self) -> Result<(), String> {
        let bytes = STANDARD
            .decode(&self.identity_key)
            .map_err(|_| "Invitation identity must be a base64 Ed25519 public key")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "Invitation identity must contain 32 bytes")?;
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| "Invalid invitation identity")?;
        if key.is_weak() {
            return Err("Weak invitation identity".into());
        }
        if self.candidates.is_empty() || self.candidates.len() > 16 {
            return Err("Invitation must contain between 1 and 16 addresses".into());
        }
        for addr in &self.candidates {
            if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast() {
                return Err(format!("Invitation contains an unusable address: {addr}"));
            }
            if let SocketAddr::V6(v6) = addr {
                if v6.ip().is_unicast_link_local() || v6.scope_id() != 0 {
                    return Err("Link-local IPv6 addresses need receiver-specific scope IDs; share a LAN IPv4 or routable IPv6 address".into());
                }
            }
            if addr.ip() == std::net::Ipv4Addr::BROADCAST {
                return Err("Broadcast addresses cannot identify a peer".into());
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String, String> {
        self.validate()?;
        let data = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(data)))
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > MAX_LENGTH {
            return Err("Invitation exceeds 8192 bytes".into());
        }
        let payload = input
            .trim()
            .strip_prefix(PREFIX)
            .ok_or("Expected a p2p-cli:v1: invitation")?;
        let bytes = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "Invitation is damaged: invalid base64")?;
        let invitation: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Invalid invitation fields: {e}"))?;
        invitation.validate()?;
        Ok(invitation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key() -> String {
        STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .as_bytes(),
        )
    }
    #[test]
    fn round_trip_identity_and_routes() {
        let invitation = Invitation::new(
            key(),
            vec![
                "192.168.1.2:8080".parse().unwrap(),
                "[2001:db8::1]:8080".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            Invitation::parse(&invitation.encode().unwrap()).unwrap(),
            invitation
        );
    }
    #[test]
    fn rejects_invalid_and_unusable_invitations() {
        for addr in [
            "0.0.0.0:8080",
            "224.0.0.1:8080",
            "127.0.0.1:0",
            "[fe80::1]:8080",
            "255.255.255.255:8080",
        ] {
            assert!(Invitation::new(key(), vec![addr.parse().unwrap()]).is_err());
        }
        assert!(Invitation::new("wrong".into(), vec!["127.0.0.1:8080".parse().unwrap()]).is_err());
        assert!(Invitation::parse(&"a".repeat(MAX_LENGTH + 1)).is_err());
        assert!(Invitation::parse("p2p-cli:v2:e30").is_err());
        assert!(Invitation::parse("p2p-cli:v1:e30").is_err());
    }
}
