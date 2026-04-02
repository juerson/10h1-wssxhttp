use super::dns;
use super::shadowsocks::AeadCipher;
use crate::config::Config;
use bytes::{BufMut, BytesMut};
use futures_util::Stream;
use pin_project_lite::pin_project;
use pretty_bytes::converter::convert;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

// ── 常量 ──────────────────────────────────────────────────────────────────────

static MAX_BUFFER_SIZE: usize = 512 * 1024;

// ── 公共协议检测函数（XhttpProxyStream 也复用）───────────────────────────────

pub fn is_trojan(buffer: &[u8]) -> bool {
    if buffer.len() <= 57 {
        return false;
    }
    buffer[56] == b'\r' && buffer[57] == b'\n' && buffer[..56].iter().all(|&b| b.is_ascii_hexdigit())
}

pub fn is_vless(buffer: &[u8]) -> bool {
    buffer.len() >= 18 && buffer[0] == 0 && !is_trojan(buffer)
}

pub fn is_shadowsocks(buffer: &[u8]) -> bool {
    match buffer[0] {
        1 => buffer.len() >= 7 && u16::from_be_bytes([buffer[5], buffer[6]]) != 0,
        3 => {
            let d = buffer[1] as usize;
            buffer.len() >= 2 + d + 2 && u16::from_be_bytes([buffer[2 + d], buffer[2 + d + 1]]) != 0
        }
        4 => buffer.len() >= 19 && u16::from_be_bytes([buffer[17], buffer[18]]) != 0,
        _ => false,
    }
}

// ── ProxyStream ───────────────────────────────────────────────────────────────

pin_project! {
    pub struct ProxyStream<'a> {
        pub config: Config,
        pub ws: &'a WebSocket,
        pub buffer: BytesMut,
        #[pin]
        pub events: EventStream<'a>,
        pub ss_decipher: Option<AeadCipher>,
        pub ss_encipher: Option<AeadCipher>,
        pub ss_expected_len: Option<usize>,
        pub ss_decrypted: BytesMut,
        pub ss_client_salt: Vec<u8>,
        pub path: String,
    }
}

impl<'a> ProxyStream<'a> {
    pub fn new(config: Config, ws: &'a WebSocket, events: EventStream<'a>, path: String) -> Self {
        Self {
            config,
            ws,
            buffer: BytesMut::with_capacity(MAX_BUFFER_SIZE),
            events,
            ss_decipher: None,
            ss_encipher: None,
            ss_expected_len: None,
            ss_decrypted: BytesMut::new(),
            ss_client_salt: vec![],
            path,
        }
    }

    pub async fn fill_buffer_until(&mut self, n: usize) -> std::io::Result<()> {
        use futures_util::StreamExt;
        while self.buffer.len() < n {
            match self.events.next().await {
                Some(Ok(WebsocketEvent::Message(msg))) => {
                    if let Some(data) = msg.bytes() {
                        self.buffer.put_slice(&data);
                    }
                }
                _ => break,
            }
        }
        Ok(())
    }

    pub fn peek_buffer(&self, n: usize) -> &[u8] {
        &self.buffer[..self.buffer.len().min(n)]
    }

    pub async fn process(&mut self) -> Result<()> {
        const PEEK_LEN: usize = 62;
        self.fill_buffer_until(PEEK_LEN).await?;
        let peeked = self.peek_buffer(PEEK_LEN);

        if peeked.len() < PEEK_LEN / 2 {
            return Err(Error::RustError("not enough buffer".into()));
        }
        if is_trojan(peeked) {
            console_log!("trojan detected!");
            return self.process_trojan().await;
        }
        if is_vless(peeked) {
            console_log!("vless detected!");
            return self.process_vless().await;
        }
        if is_shadowsocks(peeked) && self.config.enabled_shadowsocks {
            console_log!("shadowsocks plain detected!");
            return self.process_shadowsocks().await;
        }
        if self.path.contains(&self.config.ss_aead_path) {
            console_log!("path={}, using shadowsocks aead", self.path);
            return self.process_shadowsocks_aead().await;
        }
        console_log!("try vmess (catch-all)");
        self.process_vmess().await
    }

    pub async fn handle_tcp_outbound(&mut self, addr: String, port: u16) -> Result<()> {
        let mut remote = Socket::builder()
            .connect(&addr, port)
            .map_err(|e| Error::RustError(e.to_string()))?;
        remote
            .opened()
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;
        tokio::io::copy_bidirectional(self, &mut remote)
            .await
            .map(|(a, b)| {
                console_log!(
                    "copied data from {}:{}, up: {} and dl: {}",
                    addr, port, convert(a as f64), convert(b as f64)
                )
            })
            .map_err(|e| Error::RustError(e.to_string()))?;
        Ok(())
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let mut buf = BytesMut::with_capacity(65535);
        buf.resize(65535, 0u8);
        let n = self.read(&mut buf).await?;
        let data = buf.split_to(n).freeze();
        if dns::doh(&data).await.is_ok() {
            self.write(&data).await?;
        }
        Ok(())
    }
}

impl<'a> AsyncRead for ProxyStream<'a> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<tokio::io::Result<()>> {
        let mut this = self.project();
        loop {
            let plain = this.ss_decrypted.len().min(buf.remaining());
            if plain > 0 {
                buf.put_slice(&this.ss_decrypted.split_to(plain));
                return Poll::Ready(Ok(()));
            }
            if this.ss_decipher.is_some() {
                if let Some(payload) =
                    Self::decrypt_next_static(this.ss_decipher, this.ss_expected_len, this.buffer)
                {
                    this.ss_decrypted.extend_from_slice(&payload);
                    continue;
                }
            }
            if this.ss_decipher.is_none() {
                let size = this.buffer.len().min(buf.remaining());
                if size > 0 {
                    buf.put_slice(&this.buffer.split_to(size));
                    return Poll::Ready(Ok(()));
                }
            }
            match this.events.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(WebsocketEvent::Message(msg)))) => {
                    if let Some(data) = msg.bytes() {
                        this.buffer.put_slice(&data);
                    }
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Ok(WebsocketEvent::Close(_)))) => {
                    console_log!(
                        "poll_read: ws closed, buffer={} ss_decrypted={}",
                        this.buffer.len(),
                        this.ss_decrypted.len()
                    );
                    return Poll::Ready(Ok(()));
                }
                _ => {
                    console_log!("poll_read: events exhausted, buffer={}", this.buffer.len());
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<'a> AsyncWrite for ProxyStream<'a> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<tokio::io::Result<usize>> {
        const MAX_PAYLOAD_LEN: usize = 16384;
        let this = self.project();
        if let Some(ref mut enc) = this.ss_encipher {
            let mut offset = 0;
            while offset < buf.len() {
                let end = (offset + MAX_PAYLOAD_LEN).min(buf.len());
                let chunk = enc
                    .encrypt_chunk(&buf[offset..end])
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                this.ws
                    .send_with_bytes(&chunk)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                offset = end;
            }
            return Poll::Ready(Ok(buf.len()));
        }
        Poll::Ready(
            this.ws
                .send_with_bytes(buf)
                .map(|_| buf.len())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<tokio::io::Result<()>> {
        match self.ws.close::<String>(Some(1000), Some("shutdown".to_string())) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ))),
        }
    }
}
