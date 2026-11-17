// ============================================================
//  netdrop-core // network/protocol.rs
//
//  Wire-формат кадров netdrop/1:
//    [1B FrameType][4B длина payload u32 BE][12B nonce][payload (+16B tag)]
//
//  Чанки данных — 64 КиБ. Полезные нагрузки служебных кадров
//  сериализуются postcard-ом (компактный бинарный serde).
//  Кадры без шифрования (handshake / режим --no-encrypt) несут
//  нулевой nonce и plaintext-payload.
//
//  Author: SmartNet
// ============================================================

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Версия протокола (сверяется в Handshake).
pub const PROTOCOL_VERSION: u8 = 1;
/// Размеры чанков (баланс память/латентность/оверхед кадров).
pub const CHUNK_SIZE_SMALL: usize = 64 * 1024;
pub const CHUNK_SIZE_MEDIUM: usize = 256 * 1024;
pub const CHUNK_SIZE_LARGE: usize = 512 * 1024;
/// Максимально допустимый размер чанка (валидация на приёме).
pub const MAX_CHUNK_SIZE: usize = CHUNK_SIZE_LARGE;
/// Дефолтный чанк (мелкие файлы / неизвестный размер).
pub const CHUNK_SIZE: usize = CHUNK_SIZE_SMALL;
/// Длина nonce ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;
/// Длина Poly1305-тега.
pub const TAG_LEN: usize = 16;
/// Длина заголовка кадра: тип + длина + nonce.
pub const FRAME_HEADER_LEN: usize = 1 + 4 + NONCE_LEN;
/// Максимальный payload: наибольший чанк + тег + запас на служебные кадры.
pub const MAX_PAYLOAD_LEN: usize = MAX_CHUNK_SIZE + TAG_LEN + 4096;

/// Оптимальный размер чанка по общему размеру передачи:
///   < 10 МБ → 64 КиБ · 10–500 МБ → 256 КиБ · > 500 МБ → 512 КиБ.
pub fn optimal_chunk_size(total_size: u64) -> usize {
    const MB: u64 = 1024 * 1024;
    if total_size < 10 * MB {
        CHUNK_SIZE_SMALL
    } else if total_size <= 500 * MB {
        CHUNK_SIZE_MEDIUM
    } else {
        CHUNK_SIZE_LARGE
    }
}

// Коды ошибок для ErrorPayload.
pub const ERR_REJECTED: u16 = 1;
pub const ERR_HASH_MISMATCH: u16 = 2;
pub const ERR_INTERNAL: u16 = 3;
pub const ERR_VERSION: u16 = 4;

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownFrameType(u8),
    #[error("frame payload too large: {0} bytes (max {MAX_PAYLOAD_LEN})")]
    PayloadTooLarge(usize),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("control payload codec error: {0}")]
    Codec(String),
}

/// Типы кадров wire-протокола.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FrameType {
    /// Ответный ключ получателя + версия протокола (plaintext).
    Handshake = 0x01,
    /// Метаданные передачи: имя, размер, флаги.
    MetaInfo = 0x02,
    /// Чанк данных (≤ 64 КиБ до шифрования).
    DataChunk = 0x03,
    /// Подтверждение прогресса получателем.
    Ack = 0x04,
    /// Конец передачи: итоговый хэш + размер.
    Eof = 0x05,
    /// Ошибка любой стороны (код + сообщение).
    Error = 0xFF,
    /// Push-режим (доверенные устройства): привет от подключившегося отправителя.
    PushHello = 0x06,
    /// Запрос сопряжения (одноразовый секрет из QR).
    PairRequest = 0x07,
    /// Подтверждение сопряжения.
    PairAck = 0x08,
    /// Проверка доступности устройства (эхо-ответ тем же кадром).
    Ping = 0x09,
    /// Текст/ссылка между доверенными устройствами (буфер обмена).
    TextPush = 0x0A,
}

impl FrameType {
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Result<Self, ProtocolError> {
        match b {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::MetaInfo),
            0x03 => Ok(Self::DataChunk),
            0x04 => Ok(Self::Ack),
            0x05 => Ok(Self::Eof),
            0x06 => Ok(Self::PushHello),
            0x07 => Ok(Self::PairRequest),
            0x08 => Ok(Self::PairAck),
            0x09 => Ok(Self::Ping),
            0x0A => Ok(Self::TextPush),
            0xFF => Ok(Self::Error),
            other => Err(ProtocolError::UnknownFrameType(other)),
        }
    }
}

/// Кадр wire-протокола.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    pub frame_type: FrameType,
    pub nonce: [u8; NONCE_LEN],
    pub payload: Vec<u8>,
}

impl Frame {
    /// Кадр без шифрования (нулевой nonce).
    pub fn plain(frame_type: FrameType, payload: Vec<u8>) -> Self {
        Self { frame_type, nonce: [0u8; NONCE_LEN], payload }
    }

    /// Зашифрованный кадр (nonce и ciphertext от `crypto::ChunkCipher::seal`).
    pub fn sealed(frame_type: FrameType, nonce: [u8; NONCE_LEN], ciphertext: Vec<u8>) -> Self {
        Self { frame_type, nonce, payload: ciphertext }
    }

    /// Сериализовать кадр в конец буфера.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::PayloadTooLarge(self.payload.len()));
        }
        out.reserve(FRAME_HEADER_LEN + self.payload.len());
        out.push(self.frame_type.as_byte());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Попытаться разобрать кадр из начала буфера.
    /// `Ok(None)` — данных пока недостаточно (ждём ещё байты).
    /// `Ok(Some((frame, consumed)))` — кадр готов, съедено `consumed` байт.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, ProtocolError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }
        let frame_type = FrameType::from_byte(buf[0])?;
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(ProtocolError::PayloadTooLarge(len));
        }
        let total = FRAME_HEADER_LEN + len;
        if buf.len() < total {
            return Ok(None);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&buf[5..5 + NONCE_LEN]);
        let payload = buf[FRAME_HEADER_LEN..total].to_vec();
        Ok(Some((Frame { frame_type, nonce, payload }, total)))
    }
}

/// Записать кадр в асинхронный поток одним write_all (без лишних syscall).
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame: &Frame,
) -> Result<(), ProtocolError> {
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + frame.payload.len());
    frame.encode_into(&mut buf)?;
    w.write_all(&buf).await?;
    Ok(())
}

/// Прочитать ровно один кадр из асинхронного потока.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Frame, ProtocolError> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    r.read_exact(&mut header).await?;
    let frame_type = FrameType::from_byte(header[0])?;
    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge(len));
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&header[5..]);
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Frame { frame_type, nonce, payload })
}

// ---------- Полезные нагрузки служебных кадров ----------

/// Handshake от получателя (plaintext): его эфемерный ключ + версия.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct HandshakePayload {
    pub protocol_version: u8,
    pub receiver_pubkey: [u8; 32],
}

/// Метаданные передачи (шифруются, если E2E-слой включён).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MetaInfo {
    /// Имя файла или папки (без пути).
    pub name: String,
    /// Итоговый размер потока в байтах (после упаковки папки, до сжатия).
    pub size: u64,
    /// Папка (tar-поток) или одиночный файл.
    pub is_dir: bool,
    /// Число файлов внутри (для папки; 1 для файла).
    pub file_count: u32,
    /// Поток сжат ZSTD.
    pub compressed: bool,
    /// Включён прикладной E2E-слой.
    pub encrypted: bool,
    /// Размер чанка данных этой передачи (получатель заранее знает буфер).
    pub chunk_size: u32,
}

/// Подтверждение прогресса получателем.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub struct AckPayload {
    pub received_bytes: u64,
}

/// Завершение передачи: контроль целостности всего потока.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct EofPayload {
    pub total_bytes: u64,
    /// SHA-256 несжатого исходного потока.
    pub sha256: [u8; 32],
}

/// Ошибка любой из сторон.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct ErrorPayload {
    pub code: u16,
    pub message: String,
}

/// Push-привет (plaintext): подключившаяся сторона — отправитель файла.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PushHelloPayload {
    pub protocol_version: u8,
    /// Эфемерный ключ отправителя для E2E-сессии ([0;32] если без шифрования).
    pub sender_pubkey: [u8; 32],
    pub encrypted: bool,
}

/// Запрос сопряжения (plaintext): секрет из QR + имя устройства.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PairRequestPayload {
    pub secret: [u8; 16],
    pub name: String,
}

/// Подтверждение сопряжения: имя ответившего устройства.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct PairAckPayload {
    pub name: String,
}

/// Текст/ссылка для буфера обмена доверенного устройства.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct TextPushPayload {
    pub text: String,
}

/// Сериализовать служебную нагрузку (postcard).
pub fn encode_payload<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtocolError> {
    postcard::to_allocvec(v).map_err(|e| ProtocolError::Codec(e.to_string()))
}

/// Десериализовать служебную нагрузку (postcard).
pub fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    postcard::from_bytes(bytes).map_err(|e| ProtocolError::Codec(e.to_string()))
}

// ---------- Тесты ----------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn optimal_chunk_size_thresholds() {
        const MB: u64 = 1024 * 1024;
        assert_eq!(optimal_chunk_size(0), CHUNK_SIZE_SMALL);
        assert_eq!(optimal_chunk_size(10 * MB - 1), CHUNK_SIZE_SMALL);
        assert_eq!(optimal_chunk_size(10 * MB), CHUNK_SIZE_MEDIUM);
        assert_eq!(optimal_chunk_size(500 * MB), CHUNK_SIZE_MEDIUM);
        assert_eq!(optimal_chunk_size(500 * MB + 1), CHUNK_SIZE_LARGE);
        assert_eq!(optimal_chunk_size(5 * 1024 * MB), CHUNK_SIZE_LARGE);
    }

    #[test]
    fn frame_type_bytes_roundtrip() {
        for ft in [
            FrameType::Handshake,
            FrameType::MetaInfo,
            FrameType::DataChunk,
            FrameType::Ack,
            FrameType::Eof,
            FrameType::Error,
        ] {
            assert_eq!(FrameType::from_byte(ft.as_byte()).unwrap(), ft);
        }
        assert!(matches!(
            FrameType::from_byte(0x77),
            Err(ProtocolError::UnknownFrameType(0x77))
        ));
    }

    #[test]
    fn frame_encode_decode_roundtrip() {
        let f = Frame::sealed(FrameType::DataChunk, [9u8; NONCE_LEN], vec![1, 2, 3, 4, 5]);
        let mut buf = Vec::new();
        f.encode_into(&mut buf).unwrap();
        assert_eq!(buf.len(), FRAME_HEADER_LEN + 5);
        let (g, consumed) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(g, f);
    }

    #[test]
    fn frame_decode_needs_more_data() {
        let f = Frame::plain(FrameType::Ack, vec![7; 100]);
        let mut buf = Vec::new();
        f.encode_into(&mut buf).unwrap();
        // только часть заголовка
        assert!(Frame::decode(&buf[..3]).unwrap().is_none());
        // заголовок есть, payload неполный
        assert!(Frame::decode(&buf[..FRAME_HEADER_LEN + 10]).unwrap().is_none());
    }

    #[test]
    fn frame_decode_two_frames_in_buffer() {
        let f1 = Frame::plain(FrameType::MetaInfo, vec![1]);
        let f2 = Frame::plain(FrameType::DataChunk, vec![2, 2]);
        let mut buf = Vec::new();
        f1.encode_into(&mut buf).unwrap();
        f2.encode_into(&mut buf).unwrap();
        let (g1, used1) = Frame::decode(&buf).unwrap().unwrap();
        assert_eq!(g1, f1);
        let (g2, used2) = Frame::decode(&buf[used1..]).unwrap().unwrap();
        assert_eq!(g2, f2);
        assert_eq!(used1 + used2, buf.len());
    }

    #[test]
    fn oversized_payload_rejected() {
        let f = Frame::plain(FrameType::DataChunk, vec![0; MAX_PAYLOAD_LEN + 1]);
        let mut buf = Vec::new();
        assert!(matches!(
            f.encode_into(&mut buf),
            Err(ProtocolError::PayloadTooLarge(_))
        ));
        // и на приёме: заголовок с завышенной длиной
        let mut evil = vec![FrameType::DataChunk.as_byte()];
        evil.extend_from_slice(&(u32::MAX).to_be_bytes());
        evil.extend_from_slice(&[0u8; NONCE_LEN]);
        assert!(matches!(
            Frame::decode(&evil),
            Err(ProtocolError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn payload_serialization_roundtrips() {
        let hs = HandshakePayload { protocol_version: PROTOCOL_VERSION, receiver_pubkey: [3u8; 32] };
        let b = encode_payload(&hs).unwrap();
        assert_eq!(decode_payload::<HandshakePayload>(&b).unwrap(), hs);

        let meta = MetaInfo {
            name: "archive.tar".to_string(),
            size: 123_456_789,
            is_dir: true,
            file_count: 42,
            compressed: true,
            encrypted: true,
            chunk_size: CHUNK_SIZE_MEDIUM as u32,
        };
        let b = encode_payload(&meta).unwrap();
        assert_eq!(decode_payload::<MetaInfo>(&b).unwrap(), meta);

        let ack = AckPayload { received_bytes: 65536 };
        let b = encode_payload(&ack).unwrap();
        assert_eq!(decode_payload::<AckPayload>(&b).unwrap(), ack);

        let eof = EofPayload { total_bytes: 999, sha256: [0xAB; 32] };
        let b = encode_payload(&eof).unwrap();
        assert_eq!(decode_payload::<EofPayload>(&b).unwrap(), eof);

        let err = ErrorPayload { code: ERR_HASH_MISMATCH, message: "hash mismatch".to_string() };
        let b = encode_payload(&err).unwrap();
        assert_eq!(decode_payload::<ErrorPayload>(&b).unwrap(), err);
    }

    #[test]
    fn corrupted_payload_bytes_fail_decode() {
        assert!(decode_payload::<MetaInfo>(&[0xFF, 0x00]).is_err());
    }

    #[tokio::test]
    async fn async_write_read_roundtrip() {
        let (mut a, mut b) = tokio::io::duplex(256 * 1024);
        let frames = vec![
            Frame::plain(FrameType::Handshake, encode_payload(&HandshakePayload {
                protocol_version: PROTOCOL_VERSION,
                receiver_pubkey: [5u8; 32],
            }).unwrap()),
            Frame::sealed(FrameType::DataChunk, [1u8; NONCE_LEN], vec![0xEE; CHUNK_SIZE]),
            Frame::plain(FrameType::Eof, encode_payload(&EofPayload {
                total_bytes: CHUNK_SIZE as u64,
                sha256: [0u8; 32],
            }).unwrap()),
        ];
        for f in &frames {
            write_frame(&mut a, f).await.unwrap();
        }
        for f in &frames {
            let g = read_frame(&mut b).await.unwrap();
            assert_eq!(&g, f);
        }
    }
}
