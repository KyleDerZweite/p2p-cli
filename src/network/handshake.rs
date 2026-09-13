//! Ed25519 authentication of the completed Noise transcript.
use crate::crypto::IdentityManager;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

type Error = Box<dyn std::error::Error + Send + Sync>;
const MAX_FRAME: usize = 49 * 1024;
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    key: String,
    signature: String,
}

fn transcript(hash: &[u8], initiator: bool) -> Vec<u8> {
    let mut bytes = b"p2p-cli channel identity v1\0".to_vec();
    bytes.push(u8::from(initiator));
    bytes.extend_from_slice(hash);
    bytes
}

impl Proof {
    fn new(identity: &IdentityManager, hash: &[u8], initiator: bool) -> Self {
        Self {
            key: identity.get_public_key_base64(),
            signature: identity.sign(&transcript(hash, initiator)),
        }
    }
    fn verify(self, hash: &[u8], initiator: bool) -> Result<String, Error> {
        if !IdentityManager::verify_signature(
            &self.key,
            &transcript(hash, initiator),
            &self.signature,
        )? {
            return Err("identity signature does not authenticate this Noise channel".into());
        }
        Ok(self.key)
    }
}

/// The caller bounds the whole operation with a timeout. No application bytes
/// may be sent until both identities authenticate the completed transcript.
pub(super) async fn handshake(
    stream: &mut TcpStream,
    initiator: bool,
    identity: &IdentityManager,
) -> Result<(snow::TransportState, String), Error> {
    let builder = snow::Builder::new(PATTERN.parse()?);
    let keypair = builder.generate_keypair()?;
    let builder = builder
        .local_private_key(&keypair.private)?
        .prologue(b"p2p-cli authenticated sessions v1")?;
    let mut noise = if initiator {
        builder.build_initiator()?
    } else {
        builder.build_responder()?
    };
    let mut buf = vec![0; MAX_FRAME];
    if initiator {
        let n = noise.write_message(&[], &mut buf)?;
        write_frame(stream, &buf[..n]).await?;
        noise.read_message(&read_frame(stream).await?, &mut buf)?;
        let n = noise.write_message(&[], &mut buf)?;
        write_frame(stream, &buf[..n]).await?;
    } else {
        noise.read_message(&read_frame(stream).await?, &mut buf)?;
        let n = noise.write_message(&[], &mut buf)?;
        write_frame(stream, &buf[..n]).await?;
        noise.read_message(&read_frame(stream).await?, &mut buf)?;
    }
    let hash = noise.get_handshake_hash().to_vec();
    let mut transport = noise.into_transport_mode()?;
    let proof = serde_json::to_vec(&Proof::new(identity, &hash, initiator))?;
    let n = transport.write_message(&proof, &mut buf)?;
    write_frame(stream, &buf[..n]).await?;
    let n = transport.read_message(&read_frame(stream).await?, &mut buf)?;
    let peer = serde_json::from_slice::<Proof>(&buf[..n])?.verify(&hash, !initiator)?;
    Ok((transport, peer))
}

async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, Error> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > MAX_FRAME {
        return Err("invalid handshake frame length".into());
    }
    let mut buf = vec![0; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), Error> {
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proof_rejects_other_channel_role_and_identity() {
        let dir = tempfile::tempdir().unwrap();
        let alice = IdentityManager::new(dir.path().join("alice")).unwrap();
        let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
        assert_eq!(
            Proof::new(&alice, &[1; 32], true)
                .verify(&[1; 32], true)
                .unwrap(),
            alice.get_public_key_base64()
        );
        assert!(Proof::new(&alice, &[1; 32], true)
            .verify(&[2; 32], true)
            .is_err());
        assert!(Proof::new(&alice, &[1; 32], true)
            .verify(&[1; 32], false)
            .is_err());
        let mut proof = Proof::new(&alice, &[1; 32], true);
        proof.key = bob.get_public_key_base64();
        assert!(proof.verify(&[1; 32], true).is_err());
    }
    #[test]
    fn mitm_cannot_forward_identity_proof_between_two_noise_channels() {
        fn channel_hash() -> Vec<u8> {
            let initiator = snow::Builder::new(PATTERN.parse().unwrap());
            let responder = snow::Builder::new(PATTERN.parse().unwrap());
            let alice_key = initiator.generate_keypair().unwrap();
            let relay_key = responder.generate_keypair().unwrap();
            let mut alice = initiator.local_private_key(&alice_key.private).unwrap().build_initiator().unwrap();
            let mut relay = responder.local_private_key(&relay_key.private).unwrap().build_responder().unwrap();
            let mut wire = [0; 1024];
            let mut plaintext = [0; 1024];
            let n = alice.write_message(&[], &mut wire).unwrap();
            relay.read_message(&wire[..n], &mut plaintext).unwrap();
            let n = relay.write_message(&[], &mut wire).unwrap();
            alice.read_message(&wire[..n], &mut plaintext).unwrap();
            let n = alice.write_message(&[], &mut wire).unwrap();
            relay.read_message(&wire[..n], &mut plaintext).unwrap();
            assert_eq!(alice.get_handshake_hash(), relay.get_handshake_hash());
            alice.get_handshake_hash().to_vec()
        }
        let dir = tempfile::tempdir().unwrap();
        let alice = IdentityManager::new(dir.path().join("alice")).unwrap();
        let alice_to_mitm = channel_hash();
        let mitm_to_bob = channel_hash();
        assert_ne!(alice_to_mitm, mitm_to_bob);
        // A terminating intermediary can decrypt Alice's proof, but forwarding
        // it to Bob cannot authenticate the intermediary's second channel.
        let stolen_proof = Proof::new(&alice, &alice_to_mitm, true);
        assert!(stolen_proof.verify(&mitm_to_bob, true).is_err());
    }

    #[tokio::test]
    async fn authenticates_both_parties_on_real_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let alice = IdentityManager::new(dir.path().join("alice")).unwrap();
        let bob = IdentityManager::new(dir.path().join("bob")).unwrap();
        let alice_key = alice.get_public_key_base64();
        let bob_key = bob.get_public_key_base64();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            handshake(&mut stream, false, &bob).await.unwrap().1
        });
        let mut stream = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            handshake(&mut stream, true, &alice).await.unwrap().1,
            bob_key
        );
        assert_eq!(server.await.unwrap(), alice_key);
    }
}
