use super::xhttp::XhttpProxyStream;
use super::ProxyStream;
use crate::common::{parse_addr, parse_port};
use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::BufMut;
use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures_channel::mpsc;
use futures_util::StreamExt;
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;

// ── 常量 ──────────────────────────────────────────────────────────────────────
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;

// ── CipherKind ────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ProtocolVersion {
    SS2022,
    AEAD2017,
}

#[derive(Clone, Copy, Debug)]
pub enum CipherKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl CipherKind {
    pub fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
        }
    }

    pub fn from_method(method: &str) -> Option<(Self, ProtocolVersion)> {
        Some(match method {
            "2022-blake3-aes-128-gcm" => (Self::Aes128Gcm, ProtocolVersion::SS2022),
            "2022-blake3-aes-256-gcm" => (Self::Aes256Gcm, ProtocolVersion::SS2022),
            "2022-blake3-chacha20-poly1305" => (Self::ChaCha20Poly1305, ProtocolVersion::SS2022),
            "aes-128-gcm" => (Self::Aes128Gcm, ProtocolVersion::AEAD2017),
            "aes-256-gcm" => (Self::Aes256Gcm, ProtocolVersion::AEAD2017),
            "chacha20-ietf-poly1305" => (Self::ChaCha20Poly1305, ProtocolVersion::AEAD2017),
            _ => return None,
        })
    }

    pub fn derive_key_ss2022(self, psk: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut ikm = Vec::with_capacity(psk.len() + salt.len());
        ikm.extend_from_slice(psk);
        ikm.extend_from_slice(salt);
        blake3::derive_key("shadowsocks 2022 session subkey", &ikm)[..self.key_len()].to_vec()
    }

    pub fn derive_key_aead2017(self, psk: &[u8], salt: &[u8]) -> Vec<u8> {
        let key_len = self.key_len();
        let master = if psk.iter().all(|&b| b < 128) {
            evp_bytes_to_key(std::str::from_utf8(psk).unwrap_or(""), key_len)
        } else {
            psk.to_vec()
        };
        let hk = Hkdf::<Sha1>::new(Some(salt), &master);
        let mut okm = vec![0u8; key_len];
        hk.expand(b"ss-subkey", &mut okm).expect("hkdf expand");
        okm
    }
}

fn evp_bytes_to_key(password: &str, key_len: usize) -> Vec<u8> {
    let pass = password.as_bytes();
    let mut key = Vec::with_capacity(key_len);
    let mut prev = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(pass);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

// ── AeadCipher ────────────────────────────────────────────────────────────────

enum AeadInner {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

pub struct AeadCipher {
    inner: AeadInner,
    nonce: [u8; NONCE_LEN],
}

impl AeadCipher {
    pub fn new(kind: CipherKind, key: &[u8]) -> Self {
        let inner = match kind {
            CipherKind::Aes128Gcm => AeadInner::Aes128(Aes128Gcm::new_from_slice(key).unwrap()),
            CipherKind::Aes256Gcm => AeadInner::Aes256(Aes256Gcm::new_from_slice(key).unwrap()),
            CipherKind::ChaCha20Poly1305 => {
                AeadInner::ChaCha(ChaCha20Poly1305::new_from_slice(key).unwrap())
            }
        };
        Self {
            inner,
            nonce: [0u8; NONCE_LEN],
        }
    }

    pub fn crypt(&mut self, data: &[u8], encrypt: bool) -> Result<Bytes, String> {
        let nonce = Nonce::from_slice(&self.nonce);
        let result = if encrypt {
            match &self.inner {
                AeadInner::Aes128(c) => c.encrypt(nonce, data),
                AeadInner::Aes256(c) => c.encrypt(nonce, data),
                AeadInner::ChaCha(c) => c.encrypt(nonce, data),
            }
        } else {
            match &self.inner {
                AeadInner::Aes128(c) => c.decrypt(nonce, data),
                AeadInner::Aes256(c) => c.decrypt(nonce, data),
                AeadInner::ChaCha(c) => c.decrypt(nonce, data),
            }
        }
        .map_err(|e| format!("aead error: {e}"))?;

        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        Ok(Bytes::from(result))
    }

    pub fn encrypt_chunk(&mut self, data: &[u8]) -> Result<Bytes, String> {
        let len_enc = self.crypt(&(data.len() as u16).to_be_bytes(), true)?;
        let data_enc = self.crypt(data, true)?;
        let mut out = Vec::with_capacity(len_enc.len() + data_enc.len());
        out.extend_from_slice(&len_enc);
        out.extend_from_slice(&data_enc);
        Ok(Bytes::from(out))
    }
}

// ── 公共 SS 逻辑（宏展开，消除 ProxyStream / XhttpProxyStream 重复代码）───────

macro_rules! impl_ss_aead_init {
    ($self:ident, $result:ty, $err:path, $buf:expr, $fill:expr, $send:expr) => {{
        let method = $self.config.ss_method.as_deref().unwrap_or("").to_owned();
        let password = $self.config.ss_password.as_deref().unwrap_or("");

        let (kind, version) = CipherKind::from_method(&method)
            .ok_or_else(|| $err(format!("unsupported method: {method}")))?;

        let psk: Vec<u8> = if version == ProtocolVersion::SS2022 {
            STANDARD
                .decode(password)
                .map_err(|_| $err("ss: invalid base64 password".into()))?
        } else {
            password.as_bytes().to_vec()
        };

        let salt_len = kind.key_len();
        $fill($self, salt_len).await?;
        if $buf.len() < salt_len {
            return Err($err(format!(
                "ss: need {} for salt, got {}",
                salt_len,
                $buf.len()
            )));
        }

        let salt = Bytes::copy_from_slice(&$buf[..salt_len]);
        $self.ss_client_salt = salt.to_vec();
        $buf.advance(salt_len);

        let dec_key = match version {
            ProtocolVersion::SS2022 => kind.derive_key_ss2022(&psk, &salt),
            ProtocolVersion::AEAD2017 => kind.derive_key_aead2017(&psk, &salt),
        };
        $self.ss_decipher = Some(AeadCipher::new(kind, &dec_key));

        if version == ProtocolVersion::AEAD2017 {
            let mut server_salt = vec![0u8; salt_len];
            OsRng.fill_bytes(&mut server_salt);
            let enc_key = kind.derive_key_aead2017(&psk, &server_salt);
            $self.ss_encipher = Some(AeadCipher::new(kind, &enc_key));
            $send($self, server_salt)?;
        }

        Ok((kind, version)) as $result
    }};
}

macro_rules! impl_ss_parse_ss2022 {
    ($self:ident, $result:ty, $err:path, $buf:expr, $fill:expr, $send:expr) => {{
        const FIXED_PT_LEN: usize = 11;
        let fixed_ct_len = FIXED_PT_LEN + TAG_LEN;

        $fill($self, fixed_ct_len).await?;
        if $buf.len() < fixed_ct_len {
            return Err($err(format!(
                "ss2022: need {} for fixed header, got {}",
                fixed_ct_len,
                $buf.len()
            )));
        }

        let ct = $buf[..fixed_ct_len].to_vec();
        let fixed_pt = $self
            .ss_decipher
            .as_mut()
            .unwrap()
            .crypt(&ct, false)
            .map_err(|e| $err(format!("ss2022 fixed header decrypt: {e}")))?;

        if fixed_pt[0] != 0x00 {
            return Err($err(format!(
                "ss2022: expected TYPE_REQUEST(0), got {}",
                fixed_pt[0]
            )));
        }
        let ts = u64::from_be_bytes(fixed_pt[1..9].try_into().unwrap());
        let now = (js_sys::Date::now() / 1000.0) as u64;
        if now.abs_diff(ts) > 30 {
            // console_log!("ss2022: timestamp drift {}s", now.abs_diff(ts));
        }
        let var_len = u16::from_be_bytes([fixed_pt[9], fixed_pt[10]]) as usize;
        $buf.advance(fixed_ct_len);

        let var_ct_len = var_len + TAG_LEN;
        $fill($self, var_ct_len).await?;
        if $buf.len() < var_ct_len {
            return Err($err(format!(
                "ss2022: need {} for var header, got {}",
                var_ct_len,
                $buf.len()
            )));
        }

        let ct = $buf[..var_ct_len].to_vec();
        let var_pt = $self
            .ss_decipher
            .as_mut()
            .unwrap()
            .crypt(&ct, false)
            .map_err(|e| $err(format!("ss2022 var header decrypt: {e}")))?;

        let (host, port, addr_end) = parse_socks5_addr(&var_pt)
            .map_err(|e| $err(format!("ss2022 socks5 addr: {e}")))?;

        if var_pt.len() >= addr_end + 2 {
            let padding_len =
                u16::from_be_bytes([var_pt[addr_end], var_pt[addr_end + 1]]) as usize;
            let payload_start = addr_end + 2 + padding_len;
            if payload_start < var_pt.len() {
                $self.ss_decrypted.extend_from_slice(&var_pt[payload_start..]);
            }
        }
        $buf.advance(var_ct_len);

        // ── 发送 SS2022 响应头 ────────────────────────────────────────
        let method = $self.config.ss_method.as_deref().unwrap_or("");
        let password = $self.config.ss_password.as_deref().unwrap_or("");

        let (kind, _) = CipherKind::from_method(method)
            .ok_or_else(|| $err("ss2022 resp: unknown method".into()))?;

        let psk = STANDARD
            .decode(password)
            .map_err(|_| $err("ss2022 resp: bad base64".into()))?;

        let salt_len = kind.key_len();
        let mut server_salt = vec![0u8; salt_len];
        OsRng.fill_bytes(&mut server_salt);

        let enc_key = kind.derive_key_ss2022(&psk, &server_salt);
        let mut cipher = AeadCipher::new(kind, &enc_key);

        let now = (js_sys::Date::now() / 1000.0) as u64;
        let mut header_pt = Vec::with_capacity(1 + 8 + salt_len + 2);
        header_pt.push(0x01u8);
        header_pt.extend_from_slice(&now.to_be_bytes());
        header_pt.extend_from_slice(&$self.ss_client_salt);
        header_pt.extend_from_slice(&0u16.to_be_bytes());

        let header_ct = cipher
            .crypt(&header_pt, true)
            .map_err(|e| $err(format!("ss2022 resp encrypt: {e}")))?;

        let mut out = server_salt;
        out.extend_from_slice(&header_ct);
        $send($self, out)?;

        $self.ss_encipher = Some(cipher);

        let empty_ct = $self
            .ss_encipher
            .as_mut()
            .unwrap()
            .crypt(&[], true)
            .map_err(|e| $err(format!("ss2022 resp empty: {e}")))?;
        $send($self, empty_ct.to_vec())?;

        Ok((host, port)) as $result
    }};
}

macro_rules! impl_ss_parse_aead2017 {
    ($self:ident, $result:ty, $err:path, $buf:expr, $fill:expr) => {{
        let mut plain = BytesMut::new();

        loop {
            if let Some(payload) = ProxyStream::decrypt_next_static(
                &mut $self.ss_decipher,
                &mut $self.ss_expected_len,
                &mut $buf,
            ) {
                plain.extend_from_slice(&payload);

                match parse_socks5_addr(&plain) {
                    Ok((host, port, addr_end)) => {
                        if plain.len() > addr_end {
                            $self.ss_decrypted.extend_from_slice(&plain[addr_end..]);
                        }
                        return Ok((host, port)) as $result;
                    }
                    Err(_) => {
                        if plain.len() > 512 {
                            return Err($err("aead2017: request addr overflow".into())) as $result;
                        }
                    }
                }
            } else {
                let need = $buf.len() + 2 + TAG_LEN + 1;
                $fill($self, need).await?;
                if $buf.len() < 2 + TAG_LEN {
                    return Err($err("aead2017: eof before addr".into())) as $result;
                }
            }
        }
    }};
}

// ── ProxyStream impl ──────────────────────────────────────────────────────────

impl<'a> ProxyStream<'a> {
    pub async fn process_shadowsocks_aead(&mut self) -> worker::Result<()> {
        let (_kind, version) = self.aead_ss_decrypt().await?;

        let (remote_addr, remote_port) = match version {
            ProtocolVersion::SS2022 => self.parse_ss2022_request_header().await?,
            ProtocolVersion::AEAD2017 => self.parse_aead2017_request_header().await?,
        };

        let mut addr_pool = vec![(remote_addr.clone(), remote_port)];
        if !self.config.proxy_addr.is_empty() {
            addr_pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
        }
        for (addr, port) in addr_pool {
            match self.handle_tcp_outbound(addr, port).await {
                Ok(_) => return Ok(()),
                Err(e) => console_error!("ss aead fallback: {}", e),
            }
        }
        Ok(())
    }

    pub async fn aead_ss_decrypt(&mut self) -> worker::Result<(CipherKind, ProtocolVersion)> {
        async fn fill(s: &mut ProxyStream<'_>, n: usize) -> worker::Result<()> {
            s.fill_buffer_until(n)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))
        }
        fn send(s: &mut ProxyStream<'_>, data: Vec<u8>) -> worker::Result<()> {
            s.ws.send_with_bytes(&data)
                .map_err(|e| worker::Error::RustError(e.to_string()))
        }
        impl_ss_aead_init!(
            self,
            worker::Result<(CipherKind, ProtocolVersion)>,
            worker::Error::RustError,
            self.buffer,
            fill,
            send
        )
    }

    async fn parse_ss2022_request_header(&mut self) -> worker::Result<(String, u16)> {
        async fn fill(s: &mut ProxyStream<'_>, n: usize) -> worker::Result<()> {
            s.fill_buffer_until(n)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))
        }
        fn send(s: &mut ProxyStream<'_>, data: Vec<u8>) -> worker::Result<()> {
            s.ws.send_with_bytes(&data)
                .map_err(|e| worker::Error::RustError(e.to_string()))
        }
        impl_ss_parse_ss2022!(
            self,
            worker::Result<(String, u16)>,
            worker::Error::RustError,
            self.buffer,
            fill,
            send
        )
    }

    async fn parse_aead2017_request_header(&mut self) -> worker::Result<(String, u16)> {
        async fn fill(s: &mut ProxyStream<'_>, n: usize) -> worker::Result<()> {
            s.fill_buffer_until(n)
                .await
                .map_err(|e| worker::Error::RustError(e.to_string()))
        }
        impl_ss_parse_aead2017!(
            self,
            worker::Result<(String, u16)>,
            worker::Error::RustError,
            self.buffer,
            fill
        )
    }

    pub async fn process_shadowsocks(&mut self) -> worker::Result<()> {
        let remote_addr = parse_addr(self).await?;
        let remote_port = parse_port(self).await?;
        let mut addr_pool = vec![(remote_addr.clone(), remote_port)];
        if !self.config.proxy_addr.is_empty() {
            addr_pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
        }
        for (target_addr, target_port) in addr_pool {
            if let Err(e) = self.handle_tcp_outbound(target_addr, target_port).await {
                console_error!("ss plain tcp: {}", e);
            }
        }
        Ok(())
    }

    pub fn decrypt_next_static(
        decipher: &mut Option<AeadCipher>,
        expected_len: &mut Option<usize>,
        buffer: &mut BytesMut,
    ) -> Option<Bytes> {
        let dec = decipher.as_mut()?;

        if expected_len.is_none() {
            if buffer.len() < 2 + TAG_LEN {
                return None;
            }
            let plain = dec.crypt(&buffer[..2 + TAG_LEN], false).ok()?;
            *expected_len = Some(u16::from_be_bytes([plain[0], plain[1]]) as usize);
            buffer.advance(2 + TAG_LEN);
        }

        let data_len = expected_len.unwrap();
        let total = data_len + TAG_LEN;
        if buffer.len() < total {
            return None;
        }

        match dec.crypt(&buffer[..total], false) {
            Ok(payload) => {
                buffer.advance(total);
                *expected_len = None;
                Some(payload)
            }
            Err(e) => {
                console_error!("ss decrypt_next failed: {}", e);
                None
            }
        }
    }
}

// ── XhttpProxyStream impl ─────────────────────────────────────────────────────

impl XhttpProxyStream {
    pub async fn process_shadowsocks(&mut self) -> Result<()> {
        let remote_addr = self.parse_addr().await?;
        let remote_port = self.parse_port().await?;

        let mut addr_pool = vec![(remote_addr, remote_port)];
        if !self.config.proxy_addr.is_empty() {
            addr_pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
        }
        for (addr, port) in addr_pool {
            match self.handle_tcp_outbound(addr, port).await {
                Ok(_) => return Ok(()),
                Err(e) => console_error!("xhttp ss fallback: {}", e),
            }
        }
        Err(Error::RustError(
            "xhttp ss: all outbound attempts failed".into(),
        ))
    }

    pub async fn process_shadowsocks_aead(&mut self) -> Result<()> {
        let (_kind, version) = self.aead_ss_decrypt().await?;

        let (remote_addr, remote_port) = match version {
            ProtocolVersion::SS2022 => self.parse_ss2022_request_header().await?,
            ProtocolVersion::AEAD2017 => self.parse_aead2017_request_header().await?,
        };
        console_log!("xhttp ss target: {}:{}", remote_addr, remote_port);

        let mut addr_pool = vec![(remote_addr, remote_port)];
        if !self.config.proxy_addr.is_empty() {
            addr_pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
        }

        for (i, (addr, port)) in addr_pool.into_iter().enumerate() {
            match self.handle_tcp_outbound_ss_aead(addr.clone(), port).await {
                Ok(_) => return Ok(()),
                Err(e) => {
                    if i == 0 {
                        console_log!(
                            "xhttp ss aead: primary connect failed ({}:{}): {}",
                            addr,
                            port,
                            e
                        );
                    } else {
                        console_error!("xhttp ss aead fallback failed ({}:{}): {}", addr, port, e);
                    }
                }
            }
        }
        Ok(())
    }

    async fn aead_ss_decrypt(&mut self) -> Result<(CipherKind, ProtocolVersion)> {
        async fn fill(s: &mut XhttpProxyStream, n: usize) -> Result<()> {
            s.fill_up_buf(n).await
        }
        fn send(s: &mut XhttpProxyStream, data: Vec<u8>) -> Result<()> {
            s.dn_tx
                .unbounded_send(data)
                .map_err(|_| Error::RustError("xhttp ss: dn channel closed".into()))
        }
        impl_ss_aead_init!(
            self,
            Result<(CipherKind, ProtocolVersion)>,
            Error::RustError,
            self.up_buf,
            fill,
            send
        )
    }

    async fn parse_ss2022_request_header(&mut self) -> Result<(String, u16)> {
        async fn fill(s: &mut XhttpProxyStream, n: usize) -> Result<()> {
            s.fill_up_buf(n).await
        }
        fn send(s: &mut XhttpProxyStream, data: Vec<u8>) -> Result<()> {
            s.dn_tx
                .unbounded_send(data)
                .map_err(|_| Error::RustError("xhttp ss: dn channel closed".into()))
        }
        impl_ss_parse_ss2022!(
            self,
            Result<(String, u16)>,
            Error::RustError,
            self.up_buf,
            fill,
            send
        )
    }

    async fn parse_aead2017_request_header(&mut self) -> Result<(String, u16)> {
        async fn fill(s: &mut XhttpProxyStream, n: usize) -> Result<()> {
            s.fill_up_buf(n).await
        }
        impl_ss_parse_aead2017!(
            self,
            Result<(String, u16)>,
            Error::RustError,
            self.up_buf,
            fill
        )
    }

    async fn parse_addr(&mut self) -> Result<String> {
        self.fill_up_buf(1).await?;
        if self.up_buf.is_empty() {
            return Err(Error::RustError(
                "xhttp ss: no data for address type".into(),
            ));
        }

        let addr_type = self.up_buf[0];
        self.up_buf.advance(1);

        match addr_type {
            1 => {
                self.fill_up_buf(6).await?;
                if self.up_buf.len() < 6 {
                    return Err(Error::RustError(
                        "xhttp ss: insufficient data for IPv4".into(),
                    ));
                }
                let addr = format!(
                    "{}.{}.{}.{}",
                    self.up_buf[0], self.up_buf[1], self.up_buf[2], self.up_buf[3]
                );
                self.up_buf.advance(4);
                Ok(addr)
            }
            3 => {
                self.fill_up_buf(1).await?;
                if self.up_buf.is_empty() {
                    return Err(Error::RustError(
                        "xhttp ss: no data for domain length".into(),
                    ));
                }
                let domain_len = self.up_buf[0] as usize;
                self.up_buf.advance(1);

                self.fill_up_buf(domain_len).await?;
                if self.up_buf.len() < domain_len {
                    return Err(Error::RustError(
                        "xhttp ss: insufficient data for domain".into(),
                    ));
                }
                let addr = String::from_utf8_lossy(&self.up_buf[..domain_len]).to_string();
                self.up_buf.advance(domain_len);
                Ok(addr)
            }
            4 => {
                self.fill_up_buf(18).await?;
                if self.up_buf.len() < 18 {
                    return Err(Error::RustError(
                        "xhttp ss: insufficient data for IPv6".into(),
                    ));
                }
                let mut addr = String::new();
                for i in 0..8 {
                    if i > 0 {
                        addr.push(':');
                    }
                    addr.push_str(&format!(
                        "{:02x}{:02x}",
                        self.up_buf[i * 2],
                        self.up_buf[i * 2 + 1]
                    ));
                }
                self.up_buf.advance(16);
                Ok(addr)
            }
            _ => Err(Error::RustError(format!(
                "xhttp ss: unknown address type: {}",
                addr_type
            ))),
        }
    }

    async fn parse_port(&mut self) -> Result<u16> {
        self.fill_up_buf(2).await?;
        if self.up_buf.len() < 2 {
            return Err(Error::RustError(
                "xhttp ss: insufficient data for port".into(),
            ));
        }
        let port = u16::from_be_bytes([self.up_buf[0], self.up_buf[1]]);
        self.up_buf.advance(2);
        Ok(port)
    }

    async fn handle_tcp_outbound_ss_aead(&mut self, addr: String, port: u16) -> Result<()> {
        let mut remote = Socket::builder()
            .connect(&addr, port)
            .map_err(|e| Error::RustError(e.to_string()))?;
        remote
            .opened()
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        console_log!("xhttp ss aead: remote connection established");

        if !self.ss_decrypted.is_empty() {
            let data = self.ss_decrypted.split().freeze();
            console_log!(
                "xhttp ss aead: sending initial payload {} bytes",
                data.len()
            );
            remote
                .write_all(&data)
                .await
                .map_err(|e| Error::RustError(format!("ss aead initial write: {}", e)))?;
        }

        let mut decipher = self.ss_decipher.take();
        let mut expected_len = self.ss_expected_len.take();
        let mut encipher = self.ss_encipher.take();
        let mut up_buf = std::mem::take(&mut self.up_buf);

        let (dummy_tx, dummy_rx) = mpsc::unbounded::<Vec<u8>>();
        let mut up_rx = std::mem::replace(&mut self.up_rx, dummy_rx);
        drop(dummy_tx);

        let dn_tx = self.dn_tx.clone();
        let (mut remote_read, mut remote_write) = tokio::io::split(remote);

        let up_fut = async move {
            loop {
                if let Some(payload) =
                    ProxyStream::decrypt_next_static(&mut decipher, &mut expected_len, &mut up_buf)
                {
                    remote_write
                        .write_all(&payload)
                        .await
                        .map_err(|e| Error::RustError(format!("ss aead up: {}", e)))?;
                } else {
                    match up_rx.next().await {
                        Some(chunk) => up_buf.put_slice(&chunk),
                        None => {
                            console_log!("xhttp ss aead: client EOF");
                            break;
                        }
                    }
                }
            }
            remote_write.flush().await.ok();
            Ok::<_, Error>(())
        };

        let dn_fut = async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                let n = remote_read
                    .read(&mut buf)
                    .await
                    .map_err(|e| Error::RustError(format!("ss aead dn: {}", e)))?;
                if n == 0 {
                    console_log!("xhttp ss aead: remote EOF");
                    break;
                }
                let encrypted = match encipher.as_mut() {
                    Some(enc) => enc
                        .encrypt_chunk(&buf[..n])
                        .map_err(|e| Error::RustError(format!("ss aead encrypt: {}", e)))?
                        .to_vec(),
                    None => buf[..n].to_vec(),
                };
                if dn_tx.unbounded_send(encrypted).is_err() {
                    console_log!("xhttp ss aead: client disconnected");
                    break;
                }
            }
            Ok::<_, Error>(())
        };

        use futures_util::future::{select, Either};
        use std::pin::pin;

        match select(pin!(up_fut), pin!(dn_fut)).await {
            Either::Right((dn_result, _)) => {
                if let Err(e) = dn_result {
                    console_log!("xhttp ss aead: dn ended: {}", e);
                }
                Ok(())
            }
            Either::Left((up_result, dn_remaining)) => {
                if let Err(e) = up_result {
                    console_log!("xhttp ss aead: up ended: {}", e);
                }
                dn_remaining.await.ok();
                Ok(())
            }
        }
    }
}

// ── 公共 SOCKS5 地址解析 ──────────────────────────────────────────────────────

fn parse_socks5_addr(buf: &[u8]) -> std::result::Result<(String, u16, usize), &'static str> {
    if buf.is_empty() {
        return Err("empty buffer");
    }
    let (host, offset) = match buf[0] {
        1 if buf.len() >= 5 => (format!("{}.{}.{}.{}", buf[1], buf[2], buf[3], buf[4]), 5),
        3 if buf.len() >= 2 => {
            let len = buf[1] as usize;
            if buf.len() < 2 + len {
                return Err("domain too short");
            }
            (
                String::from_utf8_lossy(&buf[2..2 + len]).into_owned(),
                2 + len,
            )
        }
        4 if buf.len() >= 17 => {
            let s = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([buf[1 + i * 2], buf[2 + i * 2]])))
                .collect::<Vec<_>>()
                .join(":");
            (s, 17)
        }
        _ => return Err("unknown address type"),
    };
    if buf.len() < offset + 2 {
        return Err("port missing");
    }
    let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
    Ok((host, port, offset + 2))
}
