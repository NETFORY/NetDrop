// ============================================================
//  netdrop-core // crypto.rs
//
//  Эфемерная криптография сеанса (Perfect Forward Secrecy):
//    • X25519-пара генерируется в RAM при каждом запуске и
//      зануляется при Drop (zeroize) — на диск не попадает никогда.
//    • DH → HKDF-SHA256 → два НАПРАВЛЕННЫХ ключа ChaCha20-Poly1305
//      (sender→receiver и receiver→sender).
//    • Nonce = [1 байт направления | 3 байта нулей | 8 байт счётчика BE],
//      строго монотонный: повтор/переупорядочивание кадра = ошибка.
//    • Короткий отпечаток сессии (fingerprint) для устной сверки.
//    • Тикет `nd1…`: Base58(payload + 4 байта SHA256-чексуммы).
//
//  Author: SmartNet
// ============================================================

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

const HKDF_SALT: &[u8] = b"netdrop/v1/hkdf-salt";
const HKDF_INFO: &[u8] = b"netdrop/v1/session-keys";
const FP_CONTEXT: &[u8] = b"netdrop/v1/fingerprint";

/// Байт направления в nonce: sender → receiver.
const DIR_S2R: u8 = 0x01;
/// Байт направления в nonce: receiver → sender.
const DIR_R2S: u8 = 0x02;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("chunk encryption failed")]
    Encrypt,
    #[error("decryption failed: data corrupted, wrong key, or frame order violated")]
    Decrypt,
    #[error("nonce counter overflow — session too long")]
    NonceOverflow,
    #[error("HKDF: invalid output key length")]
    Hkdf,
}

/// Роль стороны в сессии: определяет направление nonce и порядок ключей.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Инициатор (выдал тикет, отдаёт файл).
    Sender,
    /// Принимающая сторона (ввела тикет).
    Receiver,
}

// ---------- Эфемерная пара X25519 ----------

/// Одноразовая X25519-пара. Секрет живёт только в оперативной памяти;
/// x25519-dalek зануляет его при Drop. Никогда не сериализуется.
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    /// Сгенерировать свежую пару из системного CSPRNG.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Публичный ключ (32 байта) — уходит в тикет или Handshake-кадр.
    pub fn public_bytes(&self) -> [u8; KEY_LEN] {
        self.public.to_bytes()
    }

    /// DH + HKDF → ключи сессии. Потребляет пару (self) — строгий PFS
    /// для соединений «один-к-одному».
    pub fn derive_session(
        self,
        their_public: &[u8; KEY_LEN],
        role: Role,
    ) -> Result<SessionKeys, CryptoError> {
        self.derive_session_shared(their_public, role)
    }

    /// То же, но БЕЗ потребления пары: нужен для мульти-получателей —
    /// один тикет (один pubkey), независимые сессии на каждого получателя.
    pub fn derive_session_shared(
        &self,
        their_public: &[u8; KEY_LEN],
        role: Role,
    ) -> Result<SessionKeys, CryptoError> {
        let their = PublicKey::from(*their_public);
        let shared = self.secret.diffie_hellman(&their);
        let (pub_s, pub_r) = match role {
            Role::Sender => (self.public.to_bytes(), *their_public),
            Role::Receiver => (*their_public, self.public.to_bytes()),
        };
        SessionKeys::derive(shared.as_bytes(), &pub_s, &pub_r, role)
    }
}

// ---------- Ключи сессии ----------

/// Направленные ключи сессии + отпечаток. Зануляются при Drop.
pub struct SessionKeys {
    role: Role,
    k_send: [u8; KEY_LEN],
    k_recv: [u8; KEY_LEN],
    fingerprint: String,
}

impl SessionKeys {
    fn derive(
        shared: &[u8],
        pub_s: &[u8; KEY_LEN],
        pub_r: &[u8; KEY_LEN],
        role: Role,
    ) -> Result<Self, CryptoError> {
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared);
        let mut info = Vec::with_capacity(HKDF_INFO.len() + KEY_LEN * 2);
        info.extend_from_slice(HKDF_INFO);
        info.extend_from_slice(pub_s);
        info.extend_from_slice(pub_r);
        let mut okm = [0u8; KEY_LEN * 2];
        hk.expand(&info, &mut okm).map_err(|_| CryptoError::Hkdf)?;
        let mut k_s2r = [0u8; KEY_LEN];
        let mut k_r2s = [0u8; KEY_LEN];
        k_s2r.copy_from_slice(&okm[..KEY_LEN]);
        k_r2s.copy_from_slice(&okm[KEY_LEN..]);
        okm.zeroize();
        let fingerprint = session_fingerprint(pub_s, pub_r);
        let (k_send, k_recv) = match role {
            Role::Sender => (k_s2r, k_r2s),
            Role::Receiver => (k_r2s, k_s2r),
        };
        Ok(Self { role, k_send, k_recv, fingerprint })
    }

    /// Короткий отпечаток сессии для устной сверки (вид `3f-a2-91-7c-d0`).
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Шифратор исходящих кадров (наше направление).
    pub fn sealer(&self) -> ChunkCipher {
        let dir = match self.role {
            Role::Sender => DIR_S2R,
            Role::Receiver => DIR_R2S,
        };
        ChunkCipher::new(&self.k_send, dir)
    }

    /// Дешифратор входящих кадров (встречное направление).
    pub fn opener(&self) -> ChunkCipher {
        let dir = match self.role {
            Role::Sender => DIR_R2S,
            Role::Receiver => DIR_S2R,
        };
        ChunkCipher::new(&self.k_recv, dir)
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.k_send.zeroize();
        self.k_recv.zeroize();
    }
}

/// Отпечаток сессии из пары публичных ключей (5 байт SHA256, hex-группы).
pub fn session_fingerprint(pub_s: &[u8; KEY_LEN], pub_r: &[u8; KEY_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(FP_CONTEXT);
    h.update(pub_s);
    h.update(pub_r);
    let d = h.finalize();
    d[..5]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("-")
}

// ---------- Пошаговый шифратор чанков ----------

/// ChaCha20-Poly1305 со строго монотонным nonce. Тип кадра — в AAD, поэтому
/// подмена типа кадра ломает Poly1305-тег. Один экземпляр = одно направление.
pub struct ChunkCipher {
    cipher: ChaCha20Poly1305,
    direction: u8,
    counter: u64,
}

impl ChunkCipher {
    fn new(key: &[u8; KEY_LEN], direction: u8) -> Self {
        Self {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            direction,
            counter: 0,
        }
    }

    /// Nonce текущего кадра: [направление | 0,0,0 | счётчик u64 BE].
    fn nonce_bytes(&self) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[0] = self.direction;
        n[4..].copy_from_slice(&self.counter.to_be_bytes());
        n
    }

    /// Зашифровать payload кадра. Возвращает (nonce, ciphertext+tag).
    pub fn seal(
        &mut self,
        frame_type: u8,
        plaintext: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
        let nonce = self.nonce_bytes();
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: plaintext, aad: &[frame_type] },
            )
            .map_err(|_| CryptoError::Encrypt)?;
        self.counter = self.counter.checked_add(1).ok_or(CryptoError::NonceOverflow)?;
        Ok((nonce, ct))
    }

    /// Расшифровать payload кадра. Nonce обязан совпасть с ожидаемым
    /// (направление + счётчик) — защита от replay и переупорядочивания.
    pub fn open(
        &mut self,
        frame_type: u8,
        nonce: &[u8; NONCE_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if *nonce != self.nonce_bytes() {
            return Err(CryptoError::Decrypt);
        }
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload { msg: ciphertext, aad: &[frame_type] },
            )
            .map_err(|_| CryptoError::Decrypt)?;
        self.counter = self.counter.checked_add(1).ok_or(CryptoError::NonceOverflow)?;
        Ok(pt)
    }
}

// ---------- Тикет nd1… ----------

/// Префикс тикета в человекочитаемой строке.
pub const TICKET_PREFIX: &str = "nd1";
/// Текущая версия бинарного формата тикета.
pub const TICKET_VERSION: u8 = 1;
/// Флаг: полезная нагрузка сессии шифруется прикладным E2E-слоем.
const FLAG_ENCRYPTED: u8 = 0b0000_0001;
/// Длина чексуммы (первые байты SHA256 payload) — ловит опечатки.
const CHECKSUM_LEN: usize = 4;

#[derive(thiserror::Error, Debug)]
pub enum TicketError {
    #[error("ticket must start with '{TICKET_PREFIX}'")]
    BadPrefix,
    #[error("Base58: invalid characters in ticket")]
    Base58,
    #[error("checksum mismatch — the ticket has a typo")]
    Checksum,
    #[error("unsupported ticket version: {0}")]
    Version(u8),
    #[error("ticket truncated or corrupted")]
    Truncated,
    #[error("relay URL in ticket is not valid UTF-8")]
    RelayUtf8,
}

/// Одноразовый транспортный тикет: всё, что нужно получателю для
/// прямого подключения. Формат payload (до Base58):
///   [1B версия][1B флаги][32B session pubkey][32B iroh node id]
///   [1B len relay URL][..UTF-8][1B кол-во адресов]
///   { [1B тег 4|6][4|16B IP][2B порт BE] }*
/// + 4 байта SHA256-чексуммы. Строка: "nd1" + Base58(payload‖чексумма).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    /// Включён ли прикладной E2E-слой (ChaCha20-Poly1305 поверх QUIC).
    pub encrypted: bool,
    /// Эфемерный публичный X25519-ключ отправителя.
    pub session_pubkey: [u8; KEY_LEN],
    /// iroh NodeId отправителя (ed25519 pubkey, 32 байта).
    pub node_id: [u8; 32],
    /// Домашний relay отправителя (ускоряет rendezvous), опционально.
    pub relay_url: Option<String>,
    /// Прямые socket-адреса отправителя (LAN/STUN), для hole punching.
    pub direct_addrs: Vec<std::net::SocketAddr>,
}

impl Ticket {
    /// Закодировать в строку вида `nd1…`.
    pub fn encode(&self) -> String {
        let mut p: Vec<u8> = Vec::with_capacity(128);
        p.push(TICKET_VERSION);
        p.push(if self.encrypted { FLAG_ENCRYPTED } else { 0 });
        p.extend_from_slice(&self.session_pubkey);
        p.extend_from_slice(&self.node_id);
        match self.relay_url.as_deref().filter(|u| !u.is_empty() && u.len() <= u8::MAX as usize) {
            Some(u) => {
                p.push(u.len() as u8);
                p.extend_from_slice(u.as_bytes());
            }
            None => p.push(0),
        }
        let addrs: Vec<&std::net::SocketAddr> =
            self.direct_addrs.iter().take(u8::MAX as usize).collect();
        p.push(addrs.len() as u8);
        for a in addrs {
            match a {
                std::net::SocketAddr::V4(v4) => {
                    p.push(4);
                    p.extend_from_slice(&v4.ip().octets());
                    p.extend_from_slice(&v4.port().to_be_bytes());
                }
                std::net::SocketAddr::V6(v6) => {
                    p.push(6);
                    p.extend_from_slice(&v6.ip().octets());
                    p.extend_from_slice(&v6.port().to_be_bytes());
                }
            }
        }
        let digest = Sha256::digest(&p);
        p.extend_from_slice(&digest[..CHECKSUM_LEN]);
        format!("{}{}", TICKET_PREFIX, bs58::encode(&p).into_string())
    }

    /// Раскодировать строку тикета (пробелы по краям игнорируются).
    pub fn decode(s: &str) -> Result<Self, TicketError> {
        let body = s.trim().strip_prefix(TICKET_PREFIX).ok_or(TicketError::BadPrefix)?;
        let raw = bs58::decode(body).into_vec().map_err(|_| TicketError::Base58)?;
        if raw.len() < CHECKSUM_LEN + 2 {
            return Err(TicketError::Truncated);
        }
        let (payload, cks) = raw.split_at(raw.len() - CHECKSUM_LEN);
        let digest = Sha256::digest(payload);
        if cks != &digest[..CHECKSUM_LEN] {
            return Err(TicketError::Checksum);
        }

        fn take<'a>(buf: &'a [u8], i: &mut usize, n: usize) -> Result<&'a [u8], TicketError> {
            let end = i.checked_add(n).ok_or(TicketError::Truncated)?;
            if end > buf.len() {
                return Err(TicketError::Truncated);
            }
            let s = &buf[*i..end];
            *i = end;
            Ok(s)
        }

        let mut i = 0usize;
        let version = take(payload, &mut i, 1)?[0];
        if version != TICKET_VERSION {
            return Err(TicketError::Version(version));
        }
        let flags = take(payload, &mut i, 1)?[0];
        let mut session_pubkey = [0u8; KEY_LEN];
        session_pubkey.copy_from_slice(take(payload, &mut i, KEY_LEN)?);
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(take(payload, &mut i, 32)?);
        let relay_len = take(payload, &mut i, 1)?[0] as usize;
        let relay_url = if relay_len > 0 {
            let bytes = take(payload, &mut i, relay_len)?;
            Some(String::from_utf8(bytes.to_vec()).map_err(|_| TicketError::RelayUtf8)?)
        } else {
            None
        };
        let addr_count = take(payload, &mut i, 1)?[0] as usize;
        let mut direct_addrs = Vec::with_capacity(addr_count);
        for _ in 0..addr_count {
            let tag = take(payload, &mut i, 1)?[0];
            match tag {
                4 => {
                    let ip_b = take(payload, &mut i, 4)?;
                    let port_b = take(payload, &mut i, 2)?;
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(ip_b);
                    let port = u16::from_be_bytes([port_b[0], port_b[1]]);
                    direct_addrs.push(std::net::SocketAddr::from((
                        std::net::Ipv4Addr::from(ip),
                        port,
                    )));
                }
                6 => {
                    let ip_b = take(payload, &mut i, 16)?;
                    let port_b = take(payload, &mut i, 2)?;
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(ip_b);
                    let port = u16::from_be_bytes([port_b[0], port_b[1]]);
                    direct_addrs.push(std::net::SocketAddr::from((
                        std::net::Ipv6Addr::from(ip),
                        port,
                    )));
                }
                _ => return Err(TicketError::Truncated),
            }
        }
        Ok(Self {
            encrypted: flags & FLAG_ENCRYPTED != 0,
            session_pubkey,
            node_id,
            relay_url,
            direct_addrs,
        })
    }
}

// ---------- Тесты ----------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let (pa, pb) = (a.public_bytes(), b.public_bytes());
        let s = a.derive_session(&pb, Role::Sender).unwrap();
        let r = b.derive_session(&pa, Role::Receiver).unwrap();
        (s, r)
    }

    #[test]
    fn fingerprints_match_on_both_sides() {
        let (s, r) = session_pair();
        assert_eq!(s.fingerprint(), r.fingerprint());
        assert_eq!(s.fingerprint().len(), 5 * 2 + 4); // "xx-xx-xx-xx-xx"
    }

    #[test]
    fn seal_open_roundtrip_both_directions() {
        let (s, r) = session_pair();
        let (mut s_seal, mut s_open) = (s.sealer(), s.opener());
        let (mut r_seal, mut r_open) = (r.sealer(), r.opener());

        let msg = b"hello netdrop".to_vec();
        let (n, ct) = s_seal.seal(0x03, &msg).unwrap();
        assert_ne!(ct, msg);
        assert_eq!(r_open.open(0x03, &n, &ct).unwrap(), msg);

        let (n2, ct2) = r_seal.seal(0x04, b"ack").unwrap();
        assert_eq!(s_open.open(0x04, &n2, &ct2).unwrap(), b"ack".to_vec());
    }

    #[test]
    fn nonces_are_monotonic_and_unique() {
        let (s, _r) = session_pair();
        let mut seal = s.sealer();
        let (n1, c1) = seal.seal(0x03, b"a").unwrap();
        let (n2, c2) = seal.seal(0x03, b"a").unwrap();
        assert_ne!(n1, n2);
        assert_ne!(c1, c2); // одинаковый plaintext → разный ciphertext
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (s, r) = session_pair();
        let (mut seal, mut open) = (s.sealer(), r.opener());
        let (n, mut ct) = seal.seal(0x03, b"payload").unwrap();
        ct[0] ^= 0xFF;
        assert!(open.open(0x03, &n, &ct).is_err());
    }

    #[test]
    fn wrong_frame_type_aad_is_rejected() {
        let (s, r) = session_pair();
        let (mut seal, mut open) = (s.sealer(), r.opener());
        let (n, ct) = seal.seal(0x03, b"payload").unwrap();
        assert!(open.open(0x02, &n, &ct).is_err());
    }

    #[test]
    fn out_of_order_frame_is_rejected() {
        let (s, r) = session_pair();
        let (mut seal, mut open) = (s.sealer(), r.opener());
        let (_n1, _c1) = seal.seal(0x03, b"first").unwrap();
        let (n2, c2) = seal.seal(0x03, b"second").unwrap();
        // получатель ждёт кадр №0, а пришёл №1 → replay/reorder → ошибка
        assert!(open.open(0x03, &n2, &c2).is_err());
    }

    #[test]
    fn wrong_key_cannot_decrypt() {
        let (s, _r) = session_pair();
        let (_s2, r2) = session_pair(); // другая сессия
        let (mut seal, mut open) = (s.sealer(), r2.opener());
        let (n, ct) = seal.seal(0x03, b"secret").unwrap();
        assert!(open.open(0x03, &n, &ct).is_err());
    }

    fn sample_ticket() -> Ticket {
        Ticket {
            encrypted: true,
            session_pubkey: [7u8; 32],
            node_id: [42u8; 32],
            relay_url: Some("https://relay-fsn7.sth.cx".to_string()),
            direct_addrs: vec![
                "192.168.1.10:44344".parse().unwrap(),
                "[2001:db8::1]:9000".parse().unwrap(),
            ],
        }
    }

    #[test]
    fn ticket_roundtrip() {
        let t = sample_ticket();
        let s = t.encode();
        assert!(s.starts_with(TICKET_PREFIX));
        assert_eq!(Ticket::decode(&s).unwrap(), t);
    }

    #[test]
    fn ticket_roundtrip_minimal() {
        let t = Ticket {
            encrypted: false,
            session_pubkey: [1u8; 32],
            node_id: [2u8; 32],
            relay_url: None,
            direct_addrs: Vec::new(),
        };
        assert_eq!(Ticket::decode(&t.encode()).unwrap(), t);
    }

    #[test]
    fn ticket_typo_is_caught_by_checksum() {
        let s = sample_ticket().encode();
        let mut chars: Vec<char> = s.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == '1' { '2' } else { '1' };
        let bad: String = chars.into_iter().collect();
        assert!(matches!(
            Ticket::decode(&bad),
            Err(TicketError::Checksum) | Err(TicketError::Base58)
        ));
    }

    #[test]
    fn ticket_bad_prefix_rejected() {
        assert!(matches!(Ticket::decode("xx1abc"), Err(TicketError::BadPrefix)));
    }

    #[test]
    fn ticket_whitespace_tolerated() {
        let t = sample_ticket();
        let s = format!("  {}\n", t.encode());
        assert_eq!(Ticket::decode(&s).unwrap(), t);
    }
}
