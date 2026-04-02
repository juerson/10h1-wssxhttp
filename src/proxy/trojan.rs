use super::{xhttp::XhttpProxyStream, ProxyStream};
use crate::common::{parse_addr, parse_port};
use sha2::{Digest, Sha224};
use std::sync::OnceLock;
use tokio::io::{AsyncRead, AsyncReadExt};
use worker::*;

// ── 常量 & 缓存 ───────────────────────────────────────────────────────────────

static TROJAN_HASH_CACHE: OnceLock<String> = OnceLock::new();

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        result.push(HEX_CHARS[(b >> 4) as usize] as char);
        result.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    result
}

fn trojan_hash(uuid: &uuid::Uuid) -> &'static str {
    TROJAN_HASH_CACHE.get_or_init(|| {
        let mut hasher = Sha224::new();
        hasher.update(uuid.to_string().as_bytes());
        hex_encode(&hasher.finalize())
    })
}

// ── 公共 Trojan 头部解析（两种 stream 共享）───────────────────────────────────

async fn parse_trojan_header<R: AsyncRead + Unpin>(
    r: &mut R,
    uuid: &uuid::Uuid,
) -> Result<(bool, String, u16)> {
    let mut user_id = [0u8; 56];
    r.read_exact(&mut user_id).await?;

    let expected = trojan_hash(uuid);

    let mut pass_end = 56;
    for (i, &b) in user_id.iter().enumerate() {
        if b == 0 || b == 13 || b == 10 {
            pass_end = i;
            break;
        }
    }

    let received = std::str::from_utf8(&user_id[..pass_end])
        .map_err(|_| Error::RustError("Trojan: Invalid hash format".into()))?;

    if received != expected {
        return Err(Error::RustError(format!(
            "Trojan: Invalid user ID. Expected: {}, Got: {}",
            expected, received
        )));
    }

    r.read_u16().await?;
    let is_tcp = r.read_u8().await? == 1;
    let remote_addr = parse_addr(r).await?;
    let remote_port = parse_port(r).await?;
    r.read_u16().await?;

    Ok((is_tcp, remote_addr, remote_port))
}

// ── ProxyStream impl ──────────────────────────────────────────────────────────

impl<'a> ProxyStream<'a> {
    pub async fn process_trojan(&mut self) -> Result<()> {
        let uuid = self.config.uuid;
        let (is_tcp, addr, port) = parse_trojan_header(self, &uuid).await?;

        if is_tcp {
            let mut pool = vec![(addr.clone(), port)];
            if !self.config.proxy_addr.is_empty() {
                pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
            }
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
    pub async fn process_trojan(&mut self) -> Result<()> {
        let uuid = self.config.uuid;
        let (is_tcp, addr, port) = parse_trojan_header(self, &uuid).await?;

        if is_tcp {
            let mut pool = vec![(addr, port)];
            if !self.config.proxy_addr.is_empty() {
                pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
            }
            for (a, p) in pool {
                match self.handle_tcp_outbound(a, p).await {
                    Ok(_) => return Ok(()),
                    Err(e) => console_error!("xhttp trojan fallback: {}", e),
                }
            }
        } else if let Err(e) = self.handle_udp_outbound().await {
            console_error!("error handling udp: {}", e)
        }
        Ok(())
    }
}
