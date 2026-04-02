use super::{xhttp::XhttpProxyStream, ProxyStream};
use crate::common::{parse_addr, parse_port};
use bytes::BytesMut;
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use worker::*;

// ── 常量 & 缓存 ───────────────────────────────────────────────────────────────

static VLESS_UUID_CACHE: OnceLock<[u8; 16]> = OnceLock::new();

fn get_vless_uuid_bytes(uuid: &uuid::Uuid) -> &'static [u8; 16] {
    VLESS_UUID_CACHE.get_or_init(|| uuid.as_bytes().to_owned())
}

// ── 公共 VLESS 头部解析（两种 stream 共享）────────────────────────────────────

async fn parse_vless_header<R: AsyncRead + Unpin>(
    r: &mut R,
    uuid: &uuid::Uuid,
) -> Result<(bool, u16, String)> {
    r.read_u8().await?;

    let mut user_id = [0u8; 16];
    r.read_exact(&mut user_id).await?;

    if user_id != *get_vless_uuid_bytes(uuid) {
        return Err(Error::RustError("VLESS: Invalid user ID".into()));
    }

    let m_len = r.read_u8().await?;
    let mut protobuf = BytesMut::with_capacity(m_len as usize);
    protobuf.resize(m_len as usize, 0u8);
    r.read_exact(&mut protobuf).await?;

    let is_tcp = r.read_u8().await? == 1;
    let remote_port = parse_port(r).await?;
    let remote_addr = parse_addr(r).await?;

    Ok((is_tcp, remote_port, remote_addr))
}

// ── ProxyStream impl ──────────────────────────────────────────────────────────

impl<'a> ProxyStream<'a> {
    pub async fn process_vless(&mut self) -> Result<()> {
        let uuid = self.config.uuid;
        let (is_tcp, port, addr) = parse_vless_header(self, &uuid).await?;

        if is_tcp {
            let mut pool = vec![(addr.clone(), port)];
            if !self.config.proxy_addr.is_empty() {
                pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
            }
            self.write_all(&[0u8; 2]).await?;
            for (a, p) in pool {
                if let Err(e) = self.handle_tcp_outbound(a, p).await {
                    console_error!("error handling tcp: {}", e)
                }
            }
        } else if let Err(e) = self.handle_udp_outbound().await {
            console_error!("error handling udp: {}", e)
        }
        Ok(())
    }
}

// ── XhttpProxyStream impl ─────────────────────────────────────────────────────

impl XhttpProxyStream {
    pub async fn process_vless(&mut self) -> Result<()> {
        let uuid = self.config.uuid;
        let (is_tcp, port, addr) = parse_vless_header(self, &uuid).await?;

        if is_tcp {
            let mut pool = vec![(addr, port)];
            if !self.config.proxy_addr.is_empty() {
                pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
            }
            console_log!("addr_pool: {:?}", pool);
            self.write_all(&[0u8; 2]).await?;
            for (a, p) in pool {
                match self.handle_tcp_outbound(a, p).await {
                    Ok(_) => return Ok(()),
                    Err(e) => console_error!("xhttp vless fallback: {}", e),
                }
            }
        } else if let Err(e) = self.handle_udp_outbound().await {
            console_error!("error handling udp: {}", e)
        }
        Ok(())
    }
}
