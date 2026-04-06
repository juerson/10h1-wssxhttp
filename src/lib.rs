mod common;
mod config;
mod proxy;

use crate::proxy::xhttp;
use crate::proxy::ProxyStream;
use config::{build_config, Config};
use futures_channel::mpsc;
use futures_util::StreamExt;
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;
use worker::*;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+[-:]\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());
static KV_DATA_URL: &str =
    "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";

struct ConfigResolver;

impl ConfigResolver {
    /// 解析路径并处理 KV 映射
    async fn resolve_proxy_config(req: &Request, env: &Env) -> Result<Config> {
        let mut cfg = build_config(req, env)?;
        let path = req.url()?.path().to_string();

        // 1. 提取原始 proxyip 标识
        let raw_proxyip = if path.starts_with("/pyip=") {
            path[6..].to_string()
        } else {
            path.trim_start_matches('/').to_string()
        };

        // 2. 如果是 KV 模式 (如 "US,JP")，进行复杂的解析
        let final_ip = if PROXYKV_PATTERN.is_match(&raw_proxyip) {
            Self::resolve_kv_ip(&raw_proxyip, env).await?
        } else {
            raw_proxyip
        };

        // 3. 应用 IP 到配置
        Self::apply_ip(&mut cfg, &final_ip);
        Ok(cfg)
    }

    async fn resolve_kv_ip(proxy_key_list: &str, env: &Env) -> Result<String> {
        let kv = match env.kv("mykv") {
            Ok(kv) => kv,
            Err(_) => {
                console_log!("kv not bound, using direct proxyip");
                return Ok(proxy_key_list.to_string());
            }
        };

        // 获取并缓存 KV 数据
        let proxy_kv_str = Self::get_or_fetch_kv(&kv, env).await?;
        let proxy_map: HashMap<String, Vec<String>> =
            serde_json::from_str(&proxy_kv_str).map_err(|_| Error::from("Invalid KV JSON"))?;

        // 随机逻辑
        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).ok();
        let rand_idx = rand_buf[0] as usize;

        // 选 Key
        let kvid_list: Vec<&str> = proxy_key_list.split(',').collect();
        let selected_key = kvid_list[rand_idx % kvid_list.len()];

        // 选 IP
        let ips = proxy_map
            .get(selected_key)
            .ok_or_else(|| Error::from(format!("Key {} not found", selected_key)))?;
        let selected_ip = ips[rand_idx % ips.len()].clone();

        Ok(selected_ip.replace(':', "-"))
    }

    async fn get_or_fetch_kv(kv: &worker::KvStore, env: &Env) -> Result<String> {
        if let Ok(val) = kv.get("proxy_kv").text().await {
            if let Some(s) = val {
                return Ok(s);
            }
        }
        // 缓存失效，从远程获取
        let url_str = match env.var("KV_DATA_URL") {
            Ok(v) => v.to_string(),
            Err(_) => KV_DATA_URL.to_string(),
        };
        let mut res = Fetch::Url(Url::parse(&url_str)?).send().await?;
        let text = res.text().await?;
        if res.status_code() == 200 {
            kv.put("proxy_kv", &text)?
                .expiration_ttl(86400)
                .execute()
                .await?;
            Ok(text)
        } else {
            Err(Error::from(format!(
                "error getting proxy kv: {}",
                res.status_code()
            )))
        }
    }

    fn apply_ip(cfg: &mut Config, proxyip: &str) {
        if !PROXYIP_PATTERN.is_match(proxyip) {
            return;
        }
        let delim = if proxyip.contains('-') { "-" } else { ":" };
        if let Some((addr, port_str)) = proxyip.rsplit_once(delim) {
            if let Ok(port) = port_str.parse::<u16>() {
                cfg.proxy_addr = addr.to_string();
                cfg.proxy_port = port;
            }
        }
    }
}

struct ProxyEngine;

impl ProxyEngine {
    async fn run_ws(req: Request, cfg: Config) -> Result<Response> {
        let path = req.url()?.path().to_string();
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cfg, &server, events, path).process().await {
                console_error!("WS Process Error: {}", e);
            }
        });
        Response::from_websocket(client)
    }
    async fn run_xhttp(req: Request, cfg: Config, env: &Env) -> Result<Response> {
        let (dn_rx, headers) = spawn_xhttp_core(req, cfg, env).await;
        let resp_stream = dn_rx.map(|chunk| Ok::<_, Error>(chunk));
        Ok(Response::from_stream(resp_stream)?.with_headers(headers))
    }
}

async fn spawn_xhttp_core(
    mut req: Request,
    cfg: Config,
    env: &Env,
) -> (mpsc::UnboundedReceiver<Vec<u8>>, Headers) {
    let (up_tx, up_rx) = mpsc::unbounded::<Vec<u8>>();
    let (dn_tx, dn_rx) = mpsc::unbounded::<Vec<u8>>();

    let mut body_stream = req.stream().expect("stream");
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(Ok(bytes)) = body_stream.next().await {
            if up_tx.unbounded_send(bytes.to_vec()).is_err() {
                break;
            }
        }
    });

    let path = req.path().to_string();
    wasm_bindgen_futures::spawn_local(async move {
        let mut stream = xhttp::XhttpProxyStream::new(cfg, path, up_rx, dn_tx);
        let _ = stream.process().await;
    });

    let headers = xhttp_headers(env).unwrap_or_else(|_| {
        let h = Headers::new();
        let _ = h.set("Content-Type", "application/grpc");
        h
    });
    (dn_rx, headers)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() == Method::Post {
        let cfg = build_config(&req, &env)?;
        if !cfg.xhttp_in_do {
            return ProxyEngine::run_xhttp(req, cfg, &env).await;
        }
    }
    let pathname = req.url()?.path().to_string();
    let namespace = env.durable_object("WS_CHAN")?;
    let id = namespace.id_from_name(&pathname)?;
    let stub = id.get_stub()?;
    stub.fetch_with_request(req).await
}

#[durable_object]
pub struct WsChan {
    env: Env,
}

impl DurableObject for WsChan {
    fn new(_state: State, env: Env) -> Self {
        Self { env }
    }

    async fn fetch(&self, req: Request) -> Result<Response> {
        let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
        if upgrade.eq_ignore_ascii_case("websocket") {
            let cfg = ConfigResolver::resolve_proxy_config(&req, &self.env).await?;
            ProxyEngine::run_ws(req, cfg).await
        } else if req.method() == Method::Post {
            let cfg = ConfigResolver::resolve_proxy_config(&req, &self.env).await?;
            ProxyEngine::run_xhttp(req, cfg, &self.env).await
        } else {
            Response::from_body(ResponseBody::Body("hello world!".into()))
        }
    }
}

fn xhttp_headers(env: &Env) -> Result<Headers> {
    let headers = Headers::new();
    headers.set("X-Accel-Buffering", "no")?;
    headers.set("Cache-Control", "no-store")?;
    headers.set("Connection", "Keep-Alive")?;
    headers.set("Content-Type", "application/grpc")?;

    if let Ok(v) = env.var("X_PADDING_BYTES") {
        if let Some(pad) = parse_xpadding_range(&v.to_string()) {
            headers.set("X-Padding", &pad)?;
        }
    }
    Ok(headers)
}

fn parse_xpadding_range(range: &str) -> Option<String> {
    let (lo, hi) = range.split_once('-')?;
    let lo = lo.trim().parse::<usize>().ok()?;
    let hi = hi.trim().parse::<usize>().ok()?;
    if lo > hi {
        return None;
    }
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b).ok()?;
    let n = lo + (u32::from_le_bytes(b) as usize % (hi - lo + 1));
    Some("X".repeat(n))
}
