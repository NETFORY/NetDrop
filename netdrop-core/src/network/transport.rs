// ============================================================
//  netdrop-core // network/transport.rs
//
//  P2P-транспорт на iroh 1.0 (QUIC):
//    • Endpoint на пресете N0 — дефолтные n0-реле + DNS/pkarr discovery,
//      hole punching «из коробки».
//    • Поверх добавляются наши n1-реле (RELAYS_N1) и пользовательские
//      реле — фолбэк «последней надежды» по TCP/TLS 443 при мёртвом UDP
//      (тот же паттерн, что в SmartNet p2p.rs::apply_smartnet_relays).
//    • ALPN "netdrop/1".
//
//  Author: SmartNet
// ============================================================

use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayUrl, TransportAddr};
use iroh_relay::RelayQuicConfig;

pub use iroh::endpoint::{Connection, RecvStream, SendStream};

use crate::crypto::Ticket;

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("failed to bind iroh endpoint: {0}")]
    Bind(String),
    #[error("failed to connect to sender: {0}")]
    Connect(String),
    #[error("endpoint closed — no more incoming connections")]
    Closed,
    #[error("invalid node id in ticket")]
    BadNodeId,
}

/// Обёртка над iroh Endpoint с настроенными реле и ALPN netdrop/1.
pub struct Transport {
    endpoint: Endpoint,
}

impl Transport {
    /// Поднять endpoint: пресет N0 (n0-реле + discovery + hole punching);
    /// при `include_n1` добавить n1-реле SmartHoldem, плюс `extra_relays`.
    pub async fn bind(extra_relays: &[String], include_n1: bool) -> Result<Self, TransportError> {
        Self::bind_inner(extra_relays, include_n1, None).await
    }

    /// То же, но с постоянным секретным ключом (стабильный NodeId устройства).
    pub async fn bind_with_secret(
        extra_relays: &[String],
        include_n1: bool,
        secret: [u8; 32],
    ) -> Result<Self, TransportError> {
        Self::bind_inner(extra_relays, include_n1, Some(secret)).await
    }

    async fn bind_inner(
        extra_relays: &[String],
        include_n1: bool,
        secret: Option<[u8; 32]>,
    ) -> Result<Self, TransportError> {
        let mut builder = Endpoint::builder(presets::N0).alpns(vec![crate::ALPN.to_vec()]);
        if let Some(s) = secret {
            builder = builder.secret_key(iroh::SecretKey::from_bytes(&s));
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| TransportError::Bind(e.to_string()))?;
        let builtin: &[&str] = if include_n1 { crate::RELAYS_N1 } else { &[] };
        for u in builtin
            .iter()
            .map(|s| s.to_string())
            .chain(extra_relays.iter().cloned())
        {
            match u.parse::<RelayUrl>() {
                Ok(url) => {
                    let rc = RelayConfig::new(url.clone(), Some(RelayQuicConfig::default()));
                    endpoint.insert_relay(url, Arc::new(rc)).await;
                }
                Err(e) => tracing::warn!("skipped invalid relay URL {u}: {e}"),
            }
        }
        Ok(Self { endpoint })
    }

    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Мгновенные части тикета (без ожидания online): node_id + то,
    /// что уже известно. Полные части — ticket_parts() после выхода в сеть.
    pub fn ticket_parts_now(&self) -> ([u8; 32], Option<String>, Vec<std::net::SocketAddr>) {
        let addr = self.endpoint.addr();
        let relay = addr.relay_urls().next().map(|u| u.to_string());
        let direct: Vec<std::net::SocketAddr> = addr.ip_addrs().copied().collect();
        (*addr.id.as_bytes(), relay, direct)
    }

    /// Дождаться выхода в сеть (контакт с реле, best-effort до 15с) и вернуть
    /// части тикета: (node_id, домашний relay, прямые socket-адреса).
    pub async fn ticket_parts(&self) -> ([u8; 32], Option<String>, Vec<std::net::SocketAddr>) {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.endpoint.online(),
        )
        .await;
        let addr = self.endpoint.addr();
        let relay = addr.relay_urls().next().map(|u| u.to_string());
        let direct: Vec<std::net::SocketAddr> = addr.ip_addrs().copied().collect();
        (*addr.id.as_bytes(), relay, direct)
    }

    /// Принять ОДНО входящее соединение (первого успешного получателя).
    pub async fn accept_one(&self) -> Result<Connection, TransportError> {
        loop {
            let incoming = self.endpoint.accept().await.ok_or(TransportError::Closed)?;
            match incoming.await {
                Ok(conn) => return Ok(conn),
                // неудачный handshake — ждём следующего получателя
                Err(e) => tracing::warn!("incoming connection failed: {e}"),
            }
        }
    }

    /// Подключиться к отправителю по данным тикета (relay + direct адреса;
    /// iroh сам делает hole punching и фолбэк через реле).
    pub async fn connect(&self, ticket: &Ticket) -> Result<Connection, TransportError> {
        let id = EndpointId::from_bytes(&ticket.node_id)
            .map_err(|_| TransportError::BadNodeId)?;
        let mut addrs: Vec<TransportAddr> = Vec::new();
        if let Some(r) = &ticket.relay_url {
            match r.parse::<RelayUrl>() {
                Ok(url) => addrs.push(TransportAddr::Relay(url)),
                Err(e) => tracing::warn!("relay URL from ticket is invalid: {e}"),
            }
        }
        addrs.extend(ticket.direct_addrs.iter().map(|a| TransportAddr::Ip(*a)));
        let ep_addr = EndpointAddr::from_parts(id, addrs);
        self.endpoint
            .connect(ep_addr, crate::ALPN)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))
    }

    /// Подключиться к устройству только по NodeId (адреса найдёт discovery).
    pub async fn connect_id(&self, node_id: [u8; 32]) -> Result<Connection, TransportError> {
        let id = EndpointId::from_bytes(&node_id).map_err(|_| TransportError::BadNodeId)?;
        let ep_addr = EndpointAddr::from_parts(id, Vec::<TransportAddr>::new());
        self.endpoint
            .connect(ep_addr, crate::ALPN)
            .await
            .map_err(|e| TransportError::Connect(e.to_string()))
    }

    /// Корректно закрыть endpoint (дожидается рассылки close-пакетов).
    pub async fn close(&self) {
        self.endpoint.close().await;
    }
}

/// Публичный NodeId (32 байта) из постоянного секрета устройства.
pub fn node_id_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    *iroh::SecretKey::from_bytes(secret).public().as_bytes()
}
