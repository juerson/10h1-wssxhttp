pub mod hash;

use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};
use worker::*;

pub const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: &[u8] =
    b"VMess Header AEAD Key_Length";
pub const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: &[u8] =
    b"VMess Header AEAD Nonce_Length";
pub const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY: &[u8] = b"VMess Header AEAD Key";
pub const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV: &[u8] = b"VMess Header AEAD Nonce";
pub const KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const KDFSALT_CONST_AEAD_RESP_HEADER_KEY: &[u8] = b"AEAD Resp Header Key";
pub const KDFSALT_CONST_AEAD_RESP_HEADER_IV: &[u8] = b"AEAD Resp Header IV";

#[macro_export]
macro_rules! md5 {
    ( $($v:expr),+ ) => {
        {
            let mut hash = Md5::new();
            $(
                hash.update($v);
            )*
            hash.finalize()
        }
    }
}

#[macro_export]
macro_rules! sha256 {
    ( $($v:expr),+ ) => {
        {
            let mut hash = Sha256::new();
            $(
                hash.update($v);
            )*
            hash.finalize()
        }
    }
}

pub async fn parse_addr<R: AsyncRead + std::marker::Unpin>(buf: &mut R) -> Result<String> {
    // combined addr type between Vmess, VLESS, and Trojan.
    // VLESS wouldn't connect to ipv6 address due to mismatch addr type
    let addr = match buf.read_u8().await? {
        1 => {
            let mut addr = [0u8; 4];
            buf.read_exact(&mut addr).await?;
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string()
        }
        2 | 3 => {
            let len = buf.read_u8().await?;
            let mut domain = vec![0u8; len as _];
            buf.read_exact(&mut domain).await?;
            String::from_utf8_lossy(&domain).to_string()
        }
        4 => {
            let mut addr = [0u8; 16];
            buf.read_exact(&mut addr).await?;
            Ipv6Addr::new(
                u16::from_be_bytes([addr[0], addr[1]]),
                u16::from_be_bytes([addr[2], addr[3]]),
                u16::from_be_bytes([addr[4], addr[5]]),
                u16::from_be_bytes([addr[6], addr[7]]),
                u16::from_be_bytes([addr[8], addr[9]]),
                u16::from_be_bytes([addr[10], addr[11]]),
                u16::from_be_bytes([addr[12], addr[13]]),
                u16::from_be_bytes([addr[14], addr[15]]),
            )
            .to_string()
        }
        _ => {
            return Err(Error::RustError("invalid address".to_string()));
        }
    };

    Ok(addr)
}

pub async fn parse_port<R: AsyncRead + std::marker::Unpin>(buf: &mut R) -> Result<u16> {
    let mut port = [0u8; 2];
    buf.read_exact(&mut port).await?;

    Ok(u16::from_be_bytes([port[0], port[1]]))
}
