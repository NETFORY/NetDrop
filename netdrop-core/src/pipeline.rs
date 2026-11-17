// ============================================================
//  netdrop-core // pipeline.rs
//
//  Асинхронный конвейер передачи:
//    отправитель: AsyncRead → [SHA-256 + счётчик] → ZSTD Encoder →
//                 ChaCha20-Poly1305 → кадры DataChunk → QUIC SendStream
//    получатель:  QUIC RecvStream → расшифровка → ZSTD Decoder →
//                 [SHA-256 + счётчик] → AsyncWrite (диск)
//
//  Хэш и прогресс считаются на НЕСЖАТЫХ данных (адаптеры Hashing*).
//  Размер чанка динамический (protocol::optimal_chunk_size), буферы
//  подстраиваются под него. Докачка: Preseed — префикс уже передан,
//  его хэш и смещение подмешиваются в начальное состояние конвейера.
//  Кадры Error всегда plaintext. Один переиспользуемый буфер в цикле.
//
//  Author: SmartNet
// ============================================================

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use async_compression::tokio::bufread::ZstdEncoder;
use async_compression::tokio::write::ZstdDecoder;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

use crate::crypto::{ChunkCipher, CryptoError};
use crate::network::protocol::{
    decode_payload, encode_payload, read_frame, write_frame, EofPayload, ErrorPayload, Frame,
    FrameType, ProtocolError, MAX_CHUNK_SIZE, TAG_LEN,
};

#[derive(thiserror::Error, Debug)]
pub enum PipelineError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("remote side reported an error [{code}]: {message}")]
    Remote { code: u16, message: String },
    #[error("integrity check failed (SHA-256/size mismatch) — data corrupted in transit")]
    HashMismatch,
    #[error("unexpected frame 0x{0:02x} in data stream")]
    UnexpectedFrame(u8),
}

/// Итог передачи: байты и SHA-256 несжатого потока (включая префикс докачки).
#[derive(Clone, Copy, Debug)]
pub struct TransferOutcome {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

// ---------- Докачка: захэшированный префикс ----------

/// Начальное состояние конвейера при докачке: `offset` байт уже переданы,
/// их SHA-256-состояние предвычислено (итоговый хэш останется хэшем
/// ПОЛНОГО файла).
pub struct Preseed {
    offset: u64,
    hasher: Sha256,
}

impl Preseed {
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Прочитать ровно `len` байт из `src`, захэшировав их.
    /// Побочный эффект: курсор `src` остаётся на позиции `len` —
    /// отправитель сразу продолжает стрим с места обрыва.
    pub async fn from_reader<R: AsyncRead + Unpin>(
        src: &mut R,
        len: u64,
    ) -> std::io::Result<Preseed> {
        let mut hasher = Sha256::new();
        let mut remaining = len;
        let mut buf = vec![0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let n = src.read(&mut buf[..want]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "source shorter than resume offset",
                ));
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }
        Ok(Preseed { offset: len, hasher })
    }
}

// ---------- Хэширующие адаптеры ----------

type SharedHasher = Arc<Mutex<Sha256>>;

fn hasher_digest(h: &SharedHasher) -> [u8; 32] {
    let guard = h.lock().unwrap_or_else(|p| p.into_inner());
    guard.clone().finalize().into()
}

/// AsyncRead-адаптер: прозрачно считает SHA-256 и байты исходного потока.
struct HashingReader<R> {
    inner: R,
    hasher: SharedHasher,
    count: Arc<AtomicU64>,
}

impl<R: AsyncRead + Unpin> AsyncRead for HashingReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut me.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let fresh = &buf.filled()[before..];
                if !fresh.is_empty() {
                    me.hasher
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .update(fresh);
                    me.count.fetch_add(fresh.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// AsyncWrite-адаптер: прозрачно считает SHA-256 и байты записанного потока.
struct HashingWriter<W> {
    inner: W,
    hasher: SharedHasher,
    count: Arc<AtomicU64>,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for HashingWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        match Pin::new(&mut me.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    me.hasher
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .update(&buf[..n]);
                    me.count.fetch_add(n as u64, Ordering::Relaxed);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------- Кадры: шифрование опционально ----------

/// Собрать кадр: sealed при включённом E2E-слое, иначе plaintext.
pub fn seal_frame(
    cipher: &mut Option<ChunkCipher>,
    frame_type: FrameType,
    payload: &[u8],
) -> Result<Frame, PipelineError> {
    match cipher {
        Some(c) => {
            let (nonce, ct) = c.seal(frame_type.as_byte(), payload)?;
            Ok(Frame::sealed(frame_type, nonce, ct))
        }
        None => Ok(Frame::plain(frame_type, payload.to_vec())),
    }
}

/// Раскрыть payload кадра: расшифровка при включённом E2E-слое.
pub fn open_frame(
    cipher: &mut Option<ChunkCipher>,
    frame: &Frame,
) -> Result<Vec<u8>, PipelineError> {
    match cipher {
        Some(c) => Ok(c.open(frame.frame_type.as_byte(), &frame.nonce, &frame.payload)?),
        None => Ok(frame.payload.clone()),
    }
}

/// Нормализованный размер чанка: 1 КиБ ≤ chunk ≤ MAX_CHUNK_SIZE.
fn clamp_chunk(chunk_size: usize) -> usize {
    chunk_size.clamp(1024, MAX_CHUNK_SIZE)
}

// ---------- Отправитель ----------

/// Прогнать источник через (ZSTD →) шифратор в поток кадров DataChunk,
/// завершив кадром Eof (SHA-256 + размер ПОЛНОГО несжатого потока).
/// `chunk_size` — размер чанка этой передачи (из MetaInfo).
/// `preseed` — докачка: префикс уже у получателя, `src` спозиционирован
/// на offset. `progress` растёт в исходных байтах (включая offset).
/// `rate_limit` — потолок скорости отправки, байт/сек (None/0 = без лимита).
#[allow(clippy::too_many_arguments)]
pub async fn send_stream<R, W>(
    src: R,
    dst: &mut W,
    chunk_size: usize,
    compress: bool,
    sealer: &mut Option<ChunkCipher>,
    progress: Arc<AtomicU64>,
    preseed: Option<Preseed>,
    rate_limit: Option<u64>,
) -> Result<TransferOutcome, PipelineError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin,
{
    let chunk = clamp_chunk(chunk_size);
    let (offset, hasher_init) = match preseed {
        Some(p) => (p.offset, p.hasher),
        None => (0, Sha256::new()),
    };
    let hasher: SharedHasher = Arc::new(Mutex::new(hasher_init));
    let counted = Arc::new(AtomicU64::new(offset));
    progress.store(offset, Ordering::Relaxed);
    let hr = HashingReader {
        inner: src,
        hasher: hasher.clone(),
        count: counted.clone(),
    };
    let mut reader: Box<dyn AsyncRead + Unpin + Send + '_> = if compress {
        Box::new(ZstdEncoder::new(BufReader::with_capacity(chunk, hr)))
    } else {
        Box::new(hr)
    };

    let mut buf = vec![0u8; chunk];
    let started = tokio::time::Instant::now();
    let mut sent_net: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let frame = seal_frame(sealer, FrameType::DataChunk, &buf[..n])?;
        write_frame(dst, &frame).await?;
        progress.store(counted.load(Ordering::Relaxed), Ordering::Relaxed);
        // потолок скорости: спим, если идём быстрее лимита
        if let Some(limit) = rate_limit.filter(|l| *l > 0) {
            sent_net += n as u64;
            let should = std::time::Duration::from_secs_f64(sent_net as f64 / limit as f64);
            let actual = started.elapsed();
            if should > actual {
                tokio::time::sleep(should - actual).await;
            }
        }
    }
    progress.store(counted.load(Ordering::Relaxed), Ordering::Relaxed);

    let total = counted.load(Ordering::Relaxed);
    let sha256 = hasher_digest(&hasher);
    let eof = EofPayload { total_bytes: total, sha256 };
    let frame = seal_frame(sealer, FrameType::Eof, &encode_payload(&eof)?)?;
    write_frame(dst, &frame).await?;
    Ok(TransferOutcome { bytes: total, sha256 })
}

// ---------- Получатель ----------

/// Принять поток кадров: расшифровка → (ZSTD-распаковка →) запись.
/// `chunk_size` — из MetaInfo (валидация размера кадров). `preseed` —
/// докачка: `dst` уже содержит offset байт, хэш префикса предвычислен.
/// Возвращает итог после кадра Eof, СВЕРИВ SHA-256 и размер ПОЛНОГО файла.
pub async fn receive_stream<R, W>(
    src: &mut R,
    dst: &mut W,
    chunk_size: usize,
    compressed: bool,
    opener: &mut Option<ChunkCipher>,
    progress: Arc<AtomicU64>,
    preseed: Option<Preseed>,
) -> Result<TransferOutcome, PipelineError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send,
{
    let chunk = clamp_chunk(chunk_size);
    let (offset, hasher_init) = match preseed {
        Some(p) => (p.offset, p.hasher),
        None => (0, Sha256::new()),
    };
    let hasher: SharedHasher = Arc::new(Mutex::new(hasher_init));
    progress.store(offset, Ordering::Relaxed);
    let hw = HashingWriter {
        inner: dst,
        hasher: hasher.clone(),
        count: progress.clone(),
    };
    let mut writer: Box<dyn AsyncWrite + Unpin + Send + '_> = if compressed {
        Box::new(ZstdDecoder::new(hw))
    } else {
        Box::new(hw)
    };

    loop {
        let frame = read_frame(src).await?;
        match frame.frame_type {
            FrameType::DataChunk => {
                // кадр не должен превышать заявленный в MetaInfo чанк
                if frame.payload.len() > chunk + TAG_LEN {
                    return Err(ProtocolError::PayloadTooLarge(frame.payload.len()).into());
                }
                let plain = open_frame(opener, &frame)?;
                writer.write_all(&plain).await?;
            }
            FrameType::Eof => {
                let payload = open_frame(opener, &frame)?;
                let eof: EofPayload = decode_payload(&payload)?;
                writer.shutdown().await?;
                let total = progress.load(Ordering::Relaxed);
                let sha256 = hasher_digest(&hasher);
                if total != eof.total_bytes || sha256 != eof.sha256 {
                    return Err(PipelineError::HashMismatch);
                }
                return Ok(TransferOutcome { bytes: total, sha256 });
            }
            FrameType::Error => {
                // Error-кадры всегда plaintext
                let e: ErrorPayload = decode_payload(&frame.payload)?;
                return Err(PipelineError::Remote { code: e.code, message: e.message });
            }
            other => return Err(PipelineError::UnexpectedFrame(other.as_byte())),
        }
    }
}

// ---------- Тесты ----------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::{EphemeralKeyPair, Role, SessionKeys};
    use crate::network::protocol::CHUNK_SIZE;

    fn session_pair() -> (SessionKeys, SessionKeys) {
        let a = EphemeralKeyPair::generate();
        let b = EphemeralKeyPair::generate();
        let (pa, pb) = (a.public_bytes(), b.public_bytes());
        (
            a.derive_session(&pb, Role::Sender).unwrap(),
            b.derive_session(&pa, Role::Receiver).unwrap(),
        )
    }

    /// Псевдослучайные, но сжимаемые данные (повторяющиеся блоки).
    fn sample_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| ((i / 512) % 251) as u8).collect()
    }

    async fn roundtrip(compress: bool, encrypt: bool, chunk: usize, data: Vec<u8>) {
        let (mut sealer, mut opener) = if encrypt {
            let (s, r) = session_pair();
            (Some(s.sealer()), Some(r.opener()))
        } else {
            (None, None)
        };
        // маленькая ёмкость duplex → реальный backpressure между задачами
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let src = std::io::Cursor::new(data.clone());
        let mut out: Vec<u8> = Vec::new();
        let mut dst = std::io::Cursor::new(&mut out);
        let p_tx = Arc::new(AtomicU64::new(0));
        let p_rx = Arc::new(AtomicU64::new(0));
        let (sent, received) = tokio::join!(
            send_stream(src, &mut a, chunk, compress, &mut sealer, p_tx.clone(), None, None),
            receive_stream(&mut b, &mut dst, chunk, compress, &mut opener, p_rx.clone(), None),
        );
        let sent = sent.unwrap();
        let received = received.unwrap();
        assert_eq!(sent.bytes, data.len() as u64);
        assert_eq!(received.bytes, sent.bytes);
        assert_eq!(received.sha256, sent.sha256);
        assert_eq!(out, data);
        assert_eq!(p_tx.load(Ordering::Relaxed), data.len() as u64);
        assert_eq!(p_rx.load(Ordering::Relaxed), data.len() as u64);
    }

    #[tokio::test]
    async fn roundtrip_compressed_encrypted() {
        roundtrip(true, true, CHUNK_SIZE, sample_data(300_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_plain_unencrypted() {
        roundtrip(false, false, CHUNK_SIZE, sample_data(150_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_large_chunks() {
        roundtrip(true, true, MAX_CHUNK_SIZE, sample_data(700_000)).await;
    }

    #[tokio::test]
    async fn roundtrip_empty_file() {
        roundtrip(true, true, CHUNK_SIZE, Vec::new()).await;
    }

    #[tokio::test]
    async fn resume_from_offset() {
        let data = sample_data(200_000);
        let offset = 90_000u64;
        let full_sha: [u8; 32] = Sha256::digest(&data).into();

        // отправитель: префикс захэширован, курсор остаётся на offset
        let mut src = std::io::Cursor::new(data.clone());
        let pre_tx = Preseed::from_reader(&mut src, offset).await.unwrap();
        // получатель: частичный файл уже на диске, его хэш предвычислен
        let mut existing = std::io::Cursor::new(data[..offset as usize].to_vec());
        let pre_rx = Preseed::from_reader(&mut existing, offset).await.unwrap();

        let (s, r) = session_pair();
        let (mut sealer, mut opener) = (Some(s.sealer()), Some(r.opener()));
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let mut out: Vec<u8> = data[..offset as usize].to_vec();
        let mut dst = std::io::Cursor::new(&mut out);
        dst.set_position(offset);
        let (sent, received) = tokio::join!(
            send_stream(src, &mut a, CHUNK_SIZE, true, &mut sealer,
                Arc::new(AtomicU64::new(0)), Some(pre_tx), None),
            receive_stream(&mut b, &mut dst, CHUNK_SIZE, true, &mut opener,
                Arc::new(AtomicU64::new(0)), Some(pre_rx)),
        );
        let sent = sent.unwrap();
        let received = received.unwrap();
        assert_eq!(sent.bytes, data.len() as u64);
        assert_eq!(received.bytes, data.len() as u64);
        assert_eq!(sent.sha256, full_sha);
        assert_eq!(received.sha256, full_sha);
        assert_eq!(out, data);
    }

    #[tokio::test]
    async fn wrong_session_fails_decrypt() {
        let (s, _r) = session_pair();
        let (_s2, r2) = session_pair(); // чужая сессия
        let mut sealer = Some(s.sealer());
        let mut opener = Some(r2.opener());
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        let src = std::io::Cursor::new(sample_data(10_000));
        let mut out: Vec<u8> = Vec::new();
        let mut dst = std::io::Cursor::new(&mut out);
        let (_, received) = tokio::join!(
            send_stream(src, &mut a, CHUNK_SIZE, false, &mut sealer,
                Arc::new(AtomicU64::new(0)), None, None),
            receive_stream(&mut b, &mut dst, CHUNK_SIZE, false, &mut opener,
                Arc::new(AtomicU64::new(0)), None),
        );
        assert!(matches!(received, Err(PipelineError::Crypto(_))));
    }

    #[tokio::test]
    async fn remote_error_frame_is_surfaced() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let err = ErrorPayload { code: 7, message: "stop".into() };
        write_frame(&mut a, &Frame::plain(FrameType::Error, encode_payload(&err).unwrap()))
            .await
            .unwrap();
        let mut out: Vec<u8> = Vec::new();
        let mut dst = std::io::Cursor::new(&mut out);
        let res = receive_stream(&mut b, &mut dst, CHUNK_SIZE, false, &mut None,
            Arc::new(AtomicU64::new(0)), None).await;
        assert!(matches!(res, Err(PipelineError::Remote { code: 7, .. })));
    }
}
