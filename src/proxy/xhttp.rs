use super::dns;
use super::shadowsocks::AeadCipher;
use super::websocket::{is_shadowsocks, is_trojan, is_vless};
use crate::config::Config;
use bytes::{BufMut, BytesMut};
use futures_channel::mpsc;
use futures_util::Stream;
use futures_util::StreamExt;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use worker::*;

// ── XhttpProxyStream ─────────────────────────────────────────────────────────

pub struct XhttpProxyStream {
    pub config: Config,
    pub path: String,
    pub up_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pub up_buf: BytesMut,
    pub dn_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub ss_decipher: Option<AeadCipher>,
    pub ss_encipher: Option<AeadCipher>,
    pub ss_client_salt: Vec<u8>,
    pub ss_decrypted: BytesMut,
    pub ss_expected_len: Option<usize>,
}

impl XhttpProxyStream {
    pub fn new(
        config: Config,
        path: String,
        up_rx: mpsc::UnboundedReceiver<Vec<u8>>,
        dn_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            config,
            path,
            up_rx,
            up_buf: BytesMut::with_capacity(512 * 1024),
            dn_tx,
            ss_decipher: None,
            ss_encipher: None,
            ss_client_salt: Vec::new(),
            ss_decrypted: BytesMut::new(),
            ss_expected_len: None,
        }
    }

    pub async fn process(&mut self) -> Result<()> {
        const PEEK_LEN: usize = 62;
        self.fill_up_buf(PEEK_LEN).await?;
        let peeked = &self.up_buf[..self.up_buf.len().min(PEEK_LEN)];

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

        if !self.up_buf.is_empty() {
            let data = self.up_buf.split().freeze();
            remote
                .write_all(&data)
                .await
                .map_err(|e| Error::RustError(format!("xhttp initial write: {}", e)))?;
        }

        let dn_tx = self.dn_tx.clone();
        let (dummy_tx, dummy_rx) = mpsc::unbounded::<Vec<u8>>();
        let mut up_rx = std::mem::replace(&mut self.up_rx, dummy_rx);
        drop(dummy_tx);

        let (mut remote_read, mut remote_write) = tokio::io::split(remote);

        let up_fut = async move {
            while let Some(chunk) = up_rx.next().await {
                remote_write
                    .write_all(&chunk)
                    .await
                    .map_err(|e| Error::RustError(format!("xhttp up: {}", e)))?;
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
                    .map_err(|e| Error::RustError(format!("xhttp dn: {}", e)))?;
                if n == 0 {
                    break;
                }
                if dn_tx.unbounded_send(buf[..n].to_vec()).is_err() {
                    console_log!("xhttp: client disconnected, stopping downstream");
                    break;
                }
            }
            Ok::<_, Error>(())
        };

        match futures_util::future::try_join(up_fut, dn_fut).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.to_string().contains("xhttp up") {
                    Err(e)
                } else {
                    console_log!("xhttp: connection ended normally");
                    Ok(())
                }
            }
        }
    }

    pub async fn handle_udp_outbound(&mut self) -> Result<()> {
        let data = self.up_buf.split().freeze();
        if dns::doh(&data).await.is_ok() {
            if self.dn_tx.unbounded_send(data.to_vec()).is_err() {
                console_log!("xhttp: client disconnected during UDP handling");
            }
        }
        Ok(())
    }

    pub async fn fill_up_buf(&mut self, n: usize) -> Result<()> {
        while self.up_buf.len() < n {
            match self.up_rx.next().await {
                Some(chunk) => self.up_buf.put_slice(&chunk),
                None => break,
            }
        }
        Ok(())
    }

    pub async fn ensure_buf(&mut self, n: usize) -> std::io::Result<()> {
        while self.up_buf.len() < n {
            match self.up_rx.next().await {
                Some(chunk) => self.up_buf.put_slice(&chunk),
                None => break,
            }
        }
        Ok(())
    }

    pub fn consume(&mut self, n: usize) -> bytes::Bytes {
        self.up_buf.split_to(n).freeze()
    }

    pub async fn read_bytes_from_buf(&mut self, n: usize) -> std::io::Result<bytes::Bytes> {
        self.ensure_buf(n).await?;
        Ok(self.consume(n))
    }
}

impl AsyncRead for XhttpProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.up_buf.is_empty() {
            let n = self.up_buf.len().min(buf.remaining());
            buf.put_slice(&self.up_buf.split_to(n));
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.up_rx).poll_next(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                if n == chunk.len() {
                    buf.put_slice(&chunk);
                } else {
                    buf.put_slice(&chunk[..n]);
                    self.up_buf.put_slice(&chunk[n..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for XhttpProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.dn_tx.unbounded_send(buf.to_vec()) {
            Ok(_) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp dn channel closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
