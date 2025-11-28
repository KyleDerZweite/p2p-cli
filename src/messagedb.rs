use rusqlite::{Connection, Result as SqlResult, params};
use sha2::{Sha256, Digest};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct StoredMessage {
    pub id: i64,
    pub peer_id: String,
    pub content: String,
    pub is_outgoing: bool,
    pub timestamp: String,
}

/// Trust level for a peer's identity
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TrustLevel {
    /// Unknown peer - never seen before
    Unknown = 0,
    /// Temporarily trusted for this session only
    TrustedOnce = 1,
    /// Permanently trusted (TOFU)
    Trusted = 2,
    /// Verified through external means
    Verified = 3,
}

impl From<i32> for TrustLevel {
    fn from(value: i32) -> Self {
        match value {
            1 => TrustLevel::TrustedOnce,
            2 => TrustLevel::Trusted,
            3 => TrustLevel::Verified,
            _ => TrustLevel::Unknown,
        }
    }
}

/// Information about a trusted identity
#[derive(Debug, Clone)]
pub struct TrustedIdentity {
    pub identity_key: String,
    pub fingerprint: String,
    pub alias: Option<String>,
    pub trust_level: TrustLevel,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct MessageDB {
    conn: Connection,
}

impl MessageDB {
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(db_path)?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    pub fn new_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.create_tables()?;
        Ok(db)
    }

    fn create_tables(&self) -> SqlResult<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS peers (
                peer_id TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                alias TEXT,
                last_ip TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL,
                content TEXT NOT NULL,
                is_outgoing BOOLEAN NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (peer_id) REFERENCES peers(peer_id)
            )",
            [],
        )?;

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS aliases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL,
                alias TEXT NOT NULL UNIQUE,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (peer_id) REFERENCES peers(peer_id)
            )",
            [],
        )?;

        // TOFU: Trusted identities table
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS trusted_identities (
                fingerprint TEXT PRIMARY KEY,
                identity_key TEXT NOT NULL,
                alias TEXT,
                trust_level INTEGER NOT NULL DEFAULT 0,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )?;

        Ok(())
    }

    // ==================== TOFU Identity Methods ====================

    /// Get a trusted identity by fingerprint
    pub fn get_trusted_identity(&self, fingerprint: &str) -> Result<Option<TrustedIdentity>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_key, fingerprint, alias, trust_level, first_seen, last_seen 
             FROM trusted_identities 
             WHERE fingerprint = ?1"
        )?;

        let result = stmt.query_row(params![fingerprint], |row| {
            Ok(TrustedIdentity {
                identity_key: row.get(0)?,
                fingerprint: row.get(1)?,
                alias: row.get(2)?,
                trust_level: TrustLevel::from(row.get::<_, i32>(3)?),
                first_seen: row.get(4)?,
                last_seen: row.get(5)?,
            })
        });

        match result {
            Ok(identity) => Ok(Some(identity)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Check if an identity key matches a trusted fingerprint
    pub fn verify_identity(&self, fingerprint: &str, identity_key: &str) -> Result<(bool, Option<TrustedIdentity>), Box<dyn std::error::Error>> {
        if let Some(trusted) = self.get_trusted_identity(fingerprint)? {
            if trusted.identity_key == identity_key {
                // Update last seen
                self.conn.execute(
                    "UPDATE trusted_identities SET last_seen = CURRENT_TIMESTAMP WHERE fingerprint = ?1",
                    params![fingerprint],
                )?;
                Ok((true, Some(trusted)))
            } else {
                // KEY MISMATCH - potential impersonation!
                Ok((false, Some(trusted)))
            }
        } else {
            // Unknown identity
            Ok((true, None))
        }
    }

    /// Trust a new identity (TOFU)
    pub fn trust_identity(
        &self, 
        fingerprint: &str, 
        identity_key: &str, 
        trust_level: TrustLevel,
        alias: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "INSERT OR REPLACE INTO trusted_identities (fingerprint, identity_key, alias, trust_level, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, 
                     COALESCE((SELECT first_seen FROM trusted_identities WHERE fingerprint = ?1), CURRENT_TIMESTAMP),
                     CURRENT_TIMESTAMP)",
            params![fingerprint, identity_key, alias, trust_level as i32],
        )?;
        Ok(())
    }

    /// Update the alias for a trusted identity
    pub fn set_identity_alias(&self, fingerprint: &str, alias: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "UPDATE trusted_identities SET alias = ?1 WHERE fingerprint = ?2",
            params![alias, fingerprint],
        )?;
        Ok(())
    }

    /// Remove trust from an identity
    pub fn untrust_identity(&self, fingerprint: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "DELETE FROM trusted_identities WHERE fingerprint = ?1",
            params![fingerprint],
        )?;
        Ok(())
    }

    /// Get all trusted identities
    pub fn get_all_trusted_identities(&self) -> Result<Vec<TrustedIdentity>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT identity_key, fingerprint, alias, trust_level, first_seen, last_seen 
             FROM trusted_identities 
             ORDER BY last_seen DESC"
        )?;

        let identity_iter = stmt.query_map([], |row| {
            Ok(TrustedIdentity {
                identity_key: row.get(0)?,
                fingerprint: row.get(1)?,
                alias: row.get(2)?,
                trust_level: TrustLevel::from(row.get::<_, i32>(3)?),
                first_seen: row.get(4)?,
                last_seen: row.get(5)?,
            })
        })?;

        let mut identities = Vec::new();
        for identity in identity_iter {
            identities.push(identity?);
        }

        Ok(identities)
    }

    // ==================== Original Methods ====================

    pub fn generate_peer_id(public_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(public_key.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }

    pub fn get_or_create_peer(&self, public_key: &str, ip: &str) -> Result<String, Box<dyn std::error::Error>> {
        let peer_id = Self::generate_peer_id(public_key);
        
        // Check if peer already exists
        let mut stmt = self.conn.prepare("SELECT peer_id FROM peers WHERE peer_id = ?1")?;
        let exists = stmt.exists(params![peer_id])?;
        
        if !exists {
            // Create new peer
            self.conn.execute(
                "INSERT INTO peers (peer_id, public_key, last_ip) VALUES (?1, ?2, ?3)",
                params![peer_id, public_key, ip],
            )?;
        } else {
            // Update last seen and IP
            self.conn.execute(
                "UPDATE peers SET last_ip = ?1, last_seen = CURRENT_TIMESTAMP WHERE peer_id = ?2",
                params![ip, peer_id],
            )?;
        }
        
        Ok(peer_id)
    }

    pub fn store_message(&self, peer_id: &str, content: &str, is_outgoing: bool) -> Result<i64, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "INSERT INTO messages (peer_id, content, is_outgoing) VALUES (?1, ?2, ?3)"
        )?;
        
        stmt.execute(params![peer_id, content, is_outgoing])?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn load_history(&self, peer_id: &str) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, peer_id, content, is_outgoing, timestamp 
             FROM messages 
             WHERE peer_id = ?1 
             ORDER BY timestamp ASC"
        )?;
        
        let message_iter = stmt.query_map(params![peer_id], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                peer_id: row.get(1)?,
                content: row.get(2)?,
                is_outgoing: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;
        
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message?);
        }
        
        Ok(messages)
    }

    pub fn get_peer_by_id(&self, peer_id: &str) -> Result<Option<PeerInfo>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, public_key, alias, last_ip, created_at, last_seen 
             FROM peers 
             WHERE peer_id = ?1"
        )?;
        
        let result = stmt.query_row(params![peer_id], |row| {
            Ok(PeerInfo {
                peer_id: row.get(0)?,
                public_key: row.get(1)?,
                alias: row.get(2)?,
                last_ip: row.get(3)?,
                created_at: row.get(4)?,
                last_seen: row.get(5)?,
            })
        });
        
        match result {
            Ok(peer) => Ok(Some(peer)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_peer_alias(&self, peer_id: &str, alias: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "UPDATE peers SET alias = ?1 WHERE peer_id = ?2",
            params![alias, peer_id],
        )?;
        Ok(())
    }

    pub fn get_all_peers(&self) -> Result<Vec<PeerInfo>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, public_key, alias, last_ip, created_at, last_seen 
             FROM peers 
             ORDER BY last_seen DESC"
        )?;
        
        let peer_iter = stmt.query_map([], |row| {
            Ok(PeerInfo {
                peer_id: row.get(0)?,
                public_key: row.get(1)?,
                alias: row.get(2)?,
                last_ip: row.get(3)?,
                created_at: row.get(4)?,
                last_seen: row.get(5)?,
            })
        })?;
        
        let mut peers = Vec::new();
        for peer in peer_iter {
            peers.push(peer?);
        }
        
        Ok(peers)
    }

    pub fn delete_peer(&self, peer_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Delete messages first due to foreign key constraint
        self.conn.execute("DELETE FROM messages WHERE peer_id = ?1", params![peer_id])?;
        self.conn.execute("DELETE FROM aliases WHERE peer_id = ?1", params![peer_id])?;
        self.conn.execute("DELETE FROM peers WHERE peer_id = ?1", params![peer_id])?;
        Ok(())
    }

    pub fn get_message_count(&self, peer_id: &str) -> Result<i64, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM messages WHERE peer_id = ?1")?;
        let count: i64 = stmt.query_row(params![peer_id], |row| row.get(0))?;
        Ok(count)
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: String,
    pub public_key: String,
    pub alias: Option<String>,
    pub last_ip: Option<String>,
    pub created_at: String,
    pub last_seen: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_generation() {
        let public_key = "test_public_key";
        let peer_id1 = MessageDB::generate_peer_id(public_key);
        let peer_id2 = MessageDB::generate_peer_id(public_key);
        
        assert_eq!(peer_id1, peer_id2);
        assert_eq!(peer_id1.len(), 64); // SHA-256 produces 64 char hex string
    }

    #[test]
    fn test_database_operations() -> Result<(), Box<dyn std::error::Error>> {
        let db = MessageDB::new_in_memory()?;
        
        // Test peer creation
        let peer_id = db.get_or_create_peer("test_public_key", "127.0.0.1")?;
        assert!(!peer_id.is_empty());
        
        // Test message storage
        let message_id = db.store_message(&peer_id, "encrypted_content", true)?;
        assert!(message_id > 0);
        
        // Test history loading
        let history = db.load_history(&peer_id)?;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "encrypted_content");
        assert_eq!(history[0].is_outgoing, true);
        
        Ok(())
    }

    #[test]
    fn test_alias_operations() -> Result<(), Box<dyn std::error::Error>> {
        let db = MessageDB::new_in_memory()?;
        
        let peer_id = db.get_or_create_peer("test_public_key", "127.0.0.1")?;
        db.set_peer_alias(&peer_id, "Alice")?;
        
        let peer_info = db.get_peer_by_id(&peer_id)?;
        assert!(peer_info.is_some());
        assert_eq!(peer_info.unwrap().alias, Some("Alice".to_string()));
        
        Ok(())
    }
}