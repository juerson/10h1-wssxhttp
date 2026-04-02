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
use uuid::Uuid;
use worker::*;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+[-:]\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());
static LOCATION: [&str; 9] = [
    "wnam", "enam", "sam", "weur", "eeur", "apac", "oc", "afr", "me",
];

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

fn apply_proxyip(cfg: &mut Config, proxyip: &str) {
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

fn spawn_xhttp(
    mut req: Request,
    cfg: Config,
    env: &Env,
) -> (mpsc::UnboundedReceiver<Vec<u8>>, Headers) {
    let (up_tx, up_rx) = mpsc::unbounded::<Vec<u8>>();
    let (dn_tx, dn_rx) = mpsc::unbounded::<Vec<u8>>();

    let mut body_stream = req.stream().expect("stream");
    wasm_bindgen_futures::spawn_local(async move {
        while let Some(chunk) = body_stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if up_tx.unbounded_send(bytes.to_vec()).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    console_error!("xhttp body read: {}", e);
                    break;
                }
            }
        }
    });

    let path = req.path().to_string();
    wasm_bindgen_futures::spawn_local(async move {
        let mut stream = xhttp::XhttpProxyStream::new(cfg, path, up_rx, dn_tx);
        if let Err(e) = stream.process().await {
            console_error!("xhttp process: {}", e);
        }
    });

    let headers = xhttp_headers(env).expect("headers");
    (dn_rx, headers)
}

async fn handle_xhttp(req: Request, env: Env) -> Result<Response> {
    let mut cfg = build_config(&req, &env)?;

    let path = req.url()?.path().to_string();
    let proxyip = if path.starts_with("/pyip=") {
        path[6..].to_string()
    } else if path.starts_with('/') {
        path[1..].to_string()
    } else {
        path
    };
    apply_proxyip(&mut cfg, &proxyip);

    console_log!("xhttp proxy: {}:{}", cfg.proxy_addr, cfg.proxy_port);

    let (dn_rx, headers) = spawn_xhttp(req, cfg, &env);
    let resp_stream = dn_rx.map(|chunk| Ok::<_, Error>(chunk));
    Ok(Response::from_stream(resp_stream)?.with_headers(headers))
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
            let cfg = build_config(&req, &self.env)?;
            Router::with_data(cfg)
                .on_async("/pyip=:proxyip", do_main)
                .on_async("/:proxyip", do_main)
                .on_async("/", do_main)
                .run(req, self.env.clone())
                .await
        } else if req.method() == Method::Post {
            let cfg = build_config(&req, &self.env)?;
            let (dn_rx, headers) = spawn_xhttp(req, cfg, &self.env);
            let resp_stream = dn_rx.map(|chunk| Ok::<_, Error>(chunk));
            Ok(Response::from_stream(resp_stream)?.with_headers(headers))
        } else {
            Response::from_body(ResponseBody::Body("hello world!".into()))
        }
    }
}

async fn route_to_do(req: Request, env: Env) -> Result<Response> {
    let uuid = env
        .var("ID")
        .map(|v| v.to_string().trim().parse::<Uuid>().unwrap())
        .unwrap();
    let location = env
        .var("LOCATION_HINT")
        .map(|v| {
            let val = v.to_string().trim().to_lowercase();
            if LOCATION.contains(&val.as_str()) {
                val
            } else {
                "wnam".into()
            }
        })
        .unwrap_or_else(|_| "wnam".into());

    let namespace = env.durable_object("WS_CHAN")?;
    let name = format!("user-{}-{}", location, uuid);
    let stub = namespace
        .id_from_name(&name)?
        .get_stub_with_location_hint(&location)?;

    stub.fetch_with_request(req).await
}

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: worker::Context) -> Result<Response> {
    if req.method() == Method::Post {
        let cfg = build_config(&req, &env)?;
        if cfg.xhttp_in_do {
            console_log!("进入 xhttp 模式（DO）！");
        } else {
            console_log!("进入 xhttp 模式！");
            return handle_xhttp(req, env).await;
        }
    }
    route_to_do(req, env).await
}

async fn do_main(req: Request, cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").unwrap_or(&String::new()).to_string();

    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.into()).collect();

        let kv = match cx.kv("mykv") {
            Ok(kv) => kv,
            Err(_) => {
                console_log!("kv not bound, skipping kv proxy resolution");
                return handle_proxy(req, cx, proxyip).await;
            }
        };

        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();

        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).expect("failed generating random number");

        if proxy_kv_str.is_empty() {
            let req = Fetch::Url(Url::parse(&cx.data.kv_data_url)?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?.to_string();
                kv.put("proxy_kv", &proxy_kv_str)?
                    .expiration_ttl(60 * 60 * 24)
                    .execute()
                    .await?;
            } else {
                return Err(Error::from(format!(
                    "error getting proxy kv: {}",
                    res.status_code()
                )));
            }
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        proxyip = kvid_list[kv_index].clone();
        let proxyip_index = (rand_buf[0] as usize) % proxy_kv[&proxyip].len();
        proxyip = proxy_kv[&proxyip][proxyip_index].clone().replace(':', "-");
    }

    handle_proxy(req, cx, proxyip).await
}

async fn handle_proxy(
    req: Request,
    mut cx: RouteContext<Config>,
    proxyip: String,
) -> Result<Response> {
    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    let path = req.url()?.path().to_string();

    if upgrade.eq_ignore_ascii_case("websocket") {
        apply_proxyip(&mut cx.data, &proxyip);

        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().unwrap();
            if let Err(e) = ProxyStream::new(cx.data, &server, events, path)
                .process()
                .await
            {
                console_error!("[do_main]: {}", e);
            }
        });
        Response::from_websocket(client)
    } else if req.method() == Method::Post {
        do_xhttp(req, cx.data, &cx.env).await
    } else {
        Response::from_html("hi from wasm!")
    }
}

async fn do_xhttp(req: Request, cfg: Config, env: &Env) -> Result<Response> {
    let (dn_rx, headers) = spawn_xhttp(req, cfg, env);
    let resp_stream = dn_rx.map(|chunk| Ok::<_, Error>(chunk));
    Ok(Response::from_stream(resp_stream)?.with_headers(headers))
}
