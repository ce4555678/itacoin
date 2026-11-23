//! Encrypted transport (section 2 of `docs/NETWORK_PROPOSAL.md`).
//!
//! # Handshake
//!
//! ```text
//! initiator → responder:  ek (ML-KEM-768, 1184 bytes) ‖ X25519 public key (32)
//! responder → initiator:  ct (ML-KEM-768, 1088 bytes) ‖ X25519 public key (32)
//! ```
//!
//! Both sides compute the ML-KEM shared secret and the X25519 shared secret
//! and derive the session keys from both secrets and the whole transcript,
//! including the network magic:
//!
//! ```text
//! prk     = BLAKE3-derive("ITACOIN p2p v1 handshake", ss_mlkem ‖ ss_x25519 ‖ magic ‖ ek ‖ x_i ‖ ct ‖ x_r)
//! k_i→r   = BLAKE3-keyed(prk, "initiator to responder")
//! k_r→i   = BLAKE3-keyed(prk, "responder to initiator")
//! ```
//!
//! The session is secure if either primitive is (the X-Wing idea). All keys
//! are ephemeral; peers have no long-term identity, so an active attacker can
//! sit in the middle but a passive one learns nothing, now or after a quantum
//! computer exists. Peers of another network derive different keys and fail
//! on the first frame.
//!
//! This handshake is a project-specific design and must get an independent
//! cryptographic review before mainnet.
//!
//! # Frames
//!
//! Each message is two AEAD packets with ChaCha20-Poly1305 and a per-direction
//! counter nonce: first `magic ‖ command ‖ length` (9 bytes + 16-byte tag),
//! then the payload (length + 16 bytes). The length is authenticated and
//! checked against the command's limit before the payload buffer is
//! allocated. Keys are replaced every [`REKEY_INTERVAL`] packets.

use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce, aead::Aead};
use ml_kem::{
    Ciphertext, Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey, KeyExport, MlKem768,
    Seed,
};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    NetError,
    message::{Command, Message},
};

/// Encoded ML-KEM-768 encapsulation key length.
pub const EK_BYTES: usize = 1_184;
/// Encoded ML-KEM-768 ciphertext length.
pub const CT_BYTES: usize = 1_088;
/// Packets sent with one key before it is replaced.
pub const REKEY_INTERVAL: u64 = 1 << 25;

const TAG_BYTES: usize = 16;
const FRAME_HEADER_BYTES: usize = 4 + 1 + 4;
const HANDSHAKE_CONTEXT: &str = "ITACOIN p2p v1 handshake";
const REKEY_CONTEXT: &str = "ITACOIN p2p v1 rekey";

/// One direction of an established session.
struct CipherState {
    key: Zeroizing<[u8; 32]>,
    counter: u64,
}

impl CipherState {
    fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
            counter: 0,
        }
    }

    fn next_nonce(&mut self) -> [u8; 12] {
        if self.counter == REKEY_INTERVAL {
            *self.key = blake3::derive_key(REKEY_CONTEXT, self.key.as_slice());
            self.counter = 0;
        }
        let mut nonce = [0_u8; 12];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        nonce
    }

    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.next_nonce();
        ChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()))
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("in-memory encryption cannot fail")
    }

    fn open(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetError> {
        let nonce = self.next_nonce();
        ChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()))
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|_| NetError::Protocol("frame authentication failed"))
    }
}

/// The sending half of an encrypted session.
pub struct FrameWriter<W> {
    inner: W,
    cipher: CipherState,
    magic: [u8; 4],
}

/// The receiving half of an encrypted session.
pub struct FrameReader<R> {
    inner: R,
    cipher: CipherState,
    magic: [u8; 4],
}

/// Runs the handshake on `stream` and returns the two halves of the session.
///
/// The caller bounds the time this takes.
pub async fn handshake<S>(
    stream: S,
    initiator: bool,
    magic: [u8; 4],
) -> Result<
    (
        FrameReader<tokio::io::ReadHalf<S>>,
        FrameWriter<tokio::io::WriteHalf<S>>,
    ),
    NetError,
>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut x_secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(x_secret.as_mut_slice());
    let x_secret = StaticSecret::from(*x_secret);
    let x_public = PublicKey::from(&x_secret);

    let (ek_bytes, ct_bytes, peer_x, ss_kem, initiator_x, responder_x) = if initiator {
        let mut seed = Zeroizing::new([0_u8; 64]);
        OsRng.fill_bytes(seed.as_mut_slice());
        let dk = DecapsulationKey::<MlKem768>::from_seed(Seed::from(*seed));
        let ek_bytes = dk.encapsulation_key().to_bytes().to_vec();
        let mut hello = ek_bytes.clone();
        hello.extend_from_slice(x_public.as_bytes());
        writer.write_all(&hello).await.map_err(NetError::Io)?;

        let mut reply = vec![0_u8; CT_BYTES + 32];
        reader.read_exact(&mut reply).await.map_err(NetError::Io)?;
        let ct = Ciphertext::<MlKem768>::try_from(&reply[..CT_BYTES])
            .map_err(|_| NetError::Protocol("invalid ML-KEM ciphertext"))?;
        let ss = dk.decapsulate(&ct);
        let peer = <[u8; 32]>::try_from(&reply[CT_BYTES..]).expect("32 bytes");
        (
            ek_bytes,
            reply[..CT_BYTES].to_vec(),
            peer,
            ss.to_vec(),
            *x_public.as_bytes(),
            peer,
        )
    } else {
        let mut hello = vec![0_u8; EK_BYTES + 32];
        reader.read_exact(&mut hello).await.map_err(NetError::Io)?;
        let ek_array = ml_kem::Key::<EncapsulationKey<MlKem768>>::try_from(&hello[..EK_BYTES])
            .map_err(|_| NetError::Protocol("invalid ML-KEM key"))?;
        let ek = EncapsulationKey::<MlKem768>::new(&ek_array)
            .map_err(|_| NetError::Protocol("invalid ML-KEM key"))?;
        let (ct, ss) = ek.encapsulate();
        let peer = <[u8; 32]>::try_from(&hello[EK_BYTES..]).expect("32 bytes");
        let mut reply = ct.to_vec();
        reply.extend_from_slice(x_public.as_bytes());
        writer.write_all(&reply).await.map_err(NetError::Io)?;
        (
            hello[..EK_BYTES].to_vec(),
            ct.to_vec(),
            peer,
            ss.to_vec(),
            peer,
            *x_public.as_bytes(),
        )
    };
    let ss_kem = Zeroizing::new(ss_kem);

    let shared = x_secret.diffie_hellman(&PublicKey::from(peer_x));
    if !shared.was_contributory() {
        return Err(NetError::Protocol("low-order X25519 key"));
    }

    let mut material = Zeroizing::new(Vec::with_capacity(64 + 4 + EK_BYTES + CT_BYTES + 64));
    material.extend_from_slice(&ss_kem);
    material.extend_from_slice(shared.as_bytes());
    material.extend_from_slice(&magic);
    material.extend_from_slice(&ek_bytes);
    material.extend_from_slice(&initiator_x);
    material.extend_from_slice(&ct_bytes);
    material.extend_from_slice(&responder_x);
    let prk = Zeroizing::new(blake3::derive_key(HANDSHAKE_CONTEXT, &material));
    let i_to_r = *blake3::keyed_hash(&prk, b"initiator to responder").as_bytes();
    let r_to_i = *blake3::keyed_hash(&prk, b"responder to initiator").as_bytes();
    let (send, receive) = if initiator {
        (i_to_r, r_to_i)
    } else {
        (r_to_i, i_to_r)
    };

    Ok((
        FrameReader {
            inner: reader,
            cipher: CipherState::new(receive),
            magic,
        },
        FrameWriter {
            inner: writer,
            cipher: CipherState::new(send),
            magic,
        },
    ))
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    /// Encrypts and sends one message.
    pub async fn send(&mut self, message: &Message) -> Result<(), NetError> {
        self.send_raw(message.command() as u8, &message.encode_payload())
            .await
    }

    /// Sends an arbitrary command byte and payload (tests use this to
    /// exercise the receiver's limits).
    pub async fn send_raw(&mut self, command: u8, payload: &[u8]) -> Result<(), NetError> {
        let mut header = [0_u8; FRAME_HEADER_BYTES];
        header[..4].copy_from_slice(&self.magic);
        header[4] = command;
        header[5..].copy_from_slice(
            &u32::try_from(payload.len())
                .map_err(|_| NetError::Protocol("payload too large"))?
                .to_be_bytes(),
        );
        let mut frame = self.cipher.seal(&header);
        frame.extend_from_slice(&self.cipher.seal(payload));
        self.inner.write_all(&frame).await.map_err(NetError::Io)?;
        self.inner.flush().await.map_err(NetError::Io)
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// Receives and decodes one message.
    pub async fn receive(&mut self) -> Result<Message, NetError> {
        let mut sealed = [0_u8; FRAME_HEADER_BYTES + TAG_BYTES];
        self.inner
            .read_exact(&mut sealed)
            .await
            .map_err(NetError::Io)?;
        let header = self.cipher.open(&sealed)?;
        if header[..4] != self.magic {
            return Err(NetError::Protocol("wrong network magic"));
        }
        let command = Command::from_u8(header[4])?;
        let length = u32::from_be_bytes(header[5..9].try_into().expect("4 bytes")) as usize;
        // Requirement 1.8: refuse before allocating.
        if length > command.max_payload() {
            return Err(NetError::Protocol("payload exceeds the command limit"));
        }
        let mut payload = vec![0_u8; length + TAG_BYTES];
        self.inner
            .read_exact(&mut payload)
            .await
            .map_err(NetError::Io)?;
        let payload = self.cipher.open(&payload)?;
        Message::decode(command, &payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn pair(
        magic_a: [u8; 4],
        magic_b: [u8; 4],
    ) -> (
        Result<
            (
                FrameReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
                FrameWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            ),
            NetError,
        >,
        Result<
            (
                FrameReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
                FrameWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            ),
            NetError,
        >,
    ) {
        let (a, b) = tokio::io::duplex(1 << 20);
        tokio::join!(handshake(a, true, magic_a), handshake(b, false, magic_b))
    }

    #[tokio::test]
    async fn messages_flow_both_ways() {
        let (a, b) = pair(*b"ITC0", *b"ITC0").await;
        let ((mut a_read, mut a_write), (mut b_read, mut b_write)) = (a.unwrap(), b.unwrap());
        a_write.send(&Message::Ping(7)).await.unwrap();
        assert_eq!(b_read.receive().await.unwrap(), Message::Ping(7));
        b_write.send(&Message::Pong(7)).await.unwrap();
        assert_eq!(a_read.receive().await.unwrap(), Message::Pong(7));
        for nonce in 0..100 {
            a_write.send(&Message::Ping(nonce)).await.unwrap();
            assert_eq!(b_read.receive().await.unwrap(), Message::Ping(nonce));
        }
    }

    #[tokio::test]
    async fn another_network_fails_on_the_first_frame() {
        let (a, b) = pair(*b"ITC0", *b"ITC1").await;
        let ((_, mut a_write), (mut b_read, _)) = (a.unwrap(), b.unwrap());
        a_write.send(&Message::Verack).await.unwrap();
        assert!(matches!(
            b_read.receive().await,
            Err(NetError::Protocol("frame authentication failed"))
        ));
    }

    #[tokio::test]
    async fn oversized_and_unknown_frames_are_refused_before_allocation() {
        let (a, b) = pair(*b"ITC0", *b"ITC0").await;
        let ((_, mut a_write), (mut b_read, _)) = (a.unwrap(), b.unwrap());
        // Declares 9 bytes for a ping (limit 8); the payload never needs to
        // be read for the receiver to refuse it.
        a_write
            .send_raw(Command::Ping as u8, &[0; 9])
            .await
            .unwrap();
        assert!(matches!(
            b_read.receive().await,
            Err(NetError::Protocol("payload exceeds the command limit"))
        ));

        let (a, b) = pair(*b"ITC0", *b"ITC0").await;
        let ((_, mut a_write), (mut b_read, _)) = (a.unwrap(), b.unwrap());
        a_write.send_raw(200, &[]).await.unwrap();
        assert!(matches!(
            b_read.receive().await,
            Err(NetError::Protocol("unknown command"))
        ));
    }

    #[tokio::test]
    async fn tampering_is_detected() {
        let mut writer = FrameWriter {
            inner: Vec::new(),
            cipher: CipherState::new([3; 32]),
            magic: *b"ITC0",
        };
        writer.send(&Message::Ping(9)).await.unwrap();
        let frame = writer.inner.clone();
        let read = |bytes: Vec<u8>| async move {
            let mut reader = FrameReader {
                inner: bytes.as_slice(),
                cipher: CipherState::new([3; 32]),
                magic: *b"ITC0",
            };
            reader.receive().await
        };
        assert_eq!(read(frame.clone()).await.unwrap(), Message::Ping(9));
        for position in [0, 10, frame.len() - 1] {
            let mut tampered = frame.clone();
            tampered[position] ^= 1;
            assert!(read(tampered).await.is_err(), "{position}");
        }
    }

    #[test]
    fn rekey_changes_the_key_and_resets_the_counter() {
        let mut sender = CipherState::new([5; 32]);
        let mut receiver = CipherState::new([5; 32]);
        sender.counter = REKEY_INTERVAL - 1;
        receiver.counter = REKEY_INTERVAL - 1;
        for round in 0..3_u8 {
            let sealed = sender.seal(&[round]);
            assert_eq!(receiver.open(&sealed).unwrap(), vec![round]);
        }
        assert_ne!(*sender.key, [5; 32]);
        assert_eq!(sender.counter, 2);
        // A receiver that did not rekey cannot read the new frames.
        let mut stale = CipherState::new([5; 32]);
        stale.counter = 1;
        assert!(stale.open(&sender.seal(b"x")).is_err());
    }
}
