use super::{xhttp::XhttpProxyStream, ProxyStream};
use crate::common::{
    hash, parse_addr, parse_port, KDFSALT_CONST_AEAD_RESP_HEADER_IV,
    KDFSALT_CONST_AEAD_RESP_HEADER_KEY, KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV,
    KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV,
    KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
};
use aes::cipher::KeyInit;
use aes_gcm::{
    aead::{Aead, Payload},
    Aes128Gcm,
};
use md5::{Digest, Md5};
use sha2::Sha256;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use worker::*;

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

fn vmess_md5_key(uuid: &uuid::Uuid) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(uuid.as_bytes());
    hasher.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    hasher.finalize().into()
}

fn vmess_decrypt(key: &[u8], auth_id: &[u8; 16], nonce: &[u8; 8],
                 msg: &[u8], salt_key: &[u8], salt_iv: &[u8]) -> Result<Vec<u8>> {
    let enc_key = &hash::kdf(key, &[salt_key, auth_id, nonce])[..16];
    let enc_nonce = &hash::kdf(key, &[salt_iv, auth_id, nonce])[..12];
    Aes128Gcm::new(enc_key.into())
        .decrypt(enc_nonce.into(), Payload { msg, aad: auth_id })
        .map_err(|e| Error::RustError(e.to_string()))
}

struct VmessResp {
    length: Vec<u8>,
    header: Vec<u8>,
}

fn vmess_encrypt_resp(iv: &[u8; 16], key: &[u8; 16], options: &[u8; 4]) -> Result<VmessResp> {
    let derived_key = &crate::sha256!(key)[..16];
    let iv = &crate::sha256!(iv)[..16];

    let len_key = &hash::kdf(derived_key, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY])[..16];
    let len_iv = &hash::kdf(iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV])[..12];
    let length = Aes128Gcm::new(len_key.into())
        .encrypt(len_iv.into(), &4u16.to_be_bytes()[..])
        .map_err(|e| Error::RustError(e.to_string()))?;

    let hdr_key = &hash::kdf(derived_key, &[KDFSALT_CONST_AEAD_RESP_HEADER_KEY])[..16];
    let hdr_iv = &hash::kdf(iv, &[KDFSALT_CONST_AEAD_RESP_HEADER_IV])[..12];
    let header = Aes128Gcm::new(hdr_key.into())
        .encrypt(hdr_iv.into(), &[options[0], 0x00, 0x00, 0x00][..])
        .map_err(|e| Error::RustError(e.to_string()))?;

    Ok(VmessResp { length, header })
}

// ── ProxyStream impl ──────────────────────────────────────────────────────────

impl<'a> ProxyStream<'a> {
    async fn aead_decrypt(&mut self) -> Result<Vec<u8>> {
        let key = vmess_md5_key(&self.config.uuid);

        let mut auth_id = [0u8; 16];
        self.read_exact(&mut auth_id).await?;
        let mut len = [0u8; 18];
        self.read_exact(&mut len).await?;
        let mut nonce = [0u8; 8];
        self.read_exact(&mut nonce).await?;

        let header_length = {
            let plain = vmess_decrypt(&key, &auth_id, &nonce, &len,
                KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV)?;
            ((plain[0] as u16) << 8) | (plain[1] as u16)
        };

        let cmd_len = (header_length + 16) as usize;
        let mut cmd = vec![0u8; cmd_len];
        self.read_exact(&mut cmd).await?;

        vmess_decrypt(&key, &auth_id, &nonce, &cmd,
            KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV)
    }

    pub async fn process_vmess(&mut self) -> Result<()> {
        let mut buf = Cursor::new(self.aead_decrypt().await?);

        if buf.read_u8().await? != 1 {
            return Err(Error::RustError("invalid version".into()));
        }

        let mut iv = [0u8; 16];
        buf.read_exact(&mut iv).await?;
        let mut key = [0u8; 16];
        buf.read_exact(&mut key).await?;
        let mut options = [0u8; 4];
        buf.read_exact(&mut options).await?;

        let is_tcp = buf.read_u8().await? == 0x1;
        let remote_port = parse_port(&mut buf).await?;
        let remote_addr = parse_addr(&mut buf).await?;

        let resp = vmess_encrypt_resp(&iv, &key, &options)?;
        self.write(&resp.length).await?;
        self.write(&resp.header).await?;

        if is_tcp {
            let mut pool = vec![(remote_addr.clone(), remote_port)];
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
    async fn aead_decrypt(&mut self) -> Result<Vec<u8>> {
        self.ensure_buf(42)
            .await
            .map_err(|e| Error::RustError(e.to_string()))?;

        let key = vmess_md5_key(&self.config.uuid);

        let auth_id = self.read_bytes_from_buf(16)
            .await.map_err(|e| Error::RustError(e.to_string()))?;
        let len = self.read_bytes_from_buf(18)
            .await.map_err(|e| Error::RustError(e.to_string()))?;
        let nonce = self.read_bytes_from_buf(8)
            .await.map_err(|e| Error::RustError(e.to_string()))?;

        let auth_id_ref: &[u8; 16] = auth_id.as_ref().try_into().unwrap();
        let nonce_ref: &[u8; 8] = nonce.as_ref().try_into().unwrap();

        let header_length = {
            let plain = vmess_decrypt(&key, auth_id_ref, nonce_ref, len.as_ref(),
                KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY,
                KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV)?;
            ((plain[0] as u16) << 8) | (plain[1] as u16)
        };

        let cmd_len = (header_length + 16) as usize;
        let cmd = self.read_bytes_from_buf(cmd_len)
            .await.map_err(|e| Error::RustError(e.to_string()))?;

        vmess_decrypt(&key, auth_id_ref, nonce_ref, cmd.as_ref(),
            KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY,
            KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV)
    }

    pub async fn process_vmess(&mut self) -> Result<()> {
        let mut buf = Cursor::new(self.aead_decrypt().await?);

        if buf.read_u8().await? != 1 {
            return Err(Error::RustError("invalid version".into()));
        }

        let mut iv = [0u8; 16];
        buf.read_exact(&mut iv).await?;
        let mut key = [0u8; 16];
        buf.read_exact(&mut key).await?;
        let mut options = [0u8; 4];
        buf.read_exact(&mut options).await?;

        let is_tcp = buf.read_u8().await? == 0x1;
        let remote_port = parse_port(&mut buf).await?;
        let remote_addr = parse_addr(&mut buf).await?;

        let resp = vmess_encrypt_resp(&iv, &key, &options)?;
        self.write_all(&resp.length).await?;
        self.write_all(&resp.header).await?;

        if is_tcp {
            let mut pool = vec![(remote_addr, remote_port)];
            if !self.config.proxy_addr.is_empty() {
                pool.push((self.config.proxy_addr.clone(), self.config.proxy_port));
            }
            console_log!("addr_pool: {:?}", pool);
            for (a, p) in pool {
                match self.handle_tcp_outbound(a, p).await {
                    Ok(_) => return Ok(()),
                    Err(e) => console_error!("xhttp vmess fallback: {}", e),
                }
            }
        } else if let Err(e) = self.handle_udp_outbound().await {
            console_error!("error handling udp: {}", e)
        }
        Ok(())
    }
}
