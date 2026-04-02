use ipnet::IpNet;
use std::net::IpAddr;
use uuid::Uuid;
use worker::*;

pub struct Config {
    pub uuid: Uuid,
    pub proxy_addr: String,
    pub proxy_port: u16,
    pub enabled_shadowsocks: bool,
    pub xhttp_in_do: bool,
    pub ss_method: Option<String>,
    pub ss_password: Option<String>,
    pub ss_aead_path: String,
    pub kv_data_url: String,
}

const KV_DATA_URL: &str =
    "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";

fn env_str(env: &Env, key: &str, default: &str) -> String {
    env.var(key)
        .map(|v| v.to_string().trim().to_string())
        .unwrap_or_else(|_| default.into())
}

fn env_bool(env: &Env, key: &str) -> bool {
    env.var(key)
        .map(|v| {
            let val = v.to_string().trim().to_lowercase();
            ["true", "1", "yes", "on"].contains(&val.as_str())
        })
        .unwrap_or(false)
}

pub fn build_config(req: &Request, env: &Env) -> Result<Config> {
    let uuid = env
        .var("ID")
        .map(|x| Uuid::parse_str(&x.to_string()).unwrap_or_default())?;

    let ip = req
        .headers()
        .get("CF-Connecting-IP")?
        .unwrap_or_else(|| "127.0.0.1".into());

    let enabled_ss_rules: Vec<String> = env
        .var("S_NONE_RULES")
        .map(|v| v.to_string().split(',').map(|s| s.trim().into()).collect())
        .unwrap_or_else(|_| vec!["0.0.0.0/0".into(), "::/0".into()]);

    let enabled_shadowsocks = env_bool(env, "S_NONE_ON") && ip_in_rules(&ip, &enabled_ss_rules);

    let (proxy_addr, proxy_port) = parse_host_port(&env_str(env, "HOST_PORT", ""));

    Ok(Config {
        uuid,
        proxy_addr,
        proxy_port,
        enabled_shadowsocks,
        xhttp_in_do: env_bool(env, "X_IN_DO"),
        ss_method: Some(env_str(env, "S_AEAD_METHOD", "aes-128-gcm")),
        ss_password: Some(env_str(env, "S_AEAD_PWD", "VLa7YZ2OHGZFmx1gCDVv")),
        ss_aead_path: env_str(env, "S_AEAD_PATH", "/ss"),
        kv_data_url: env_str(env, "KV_DATA_URL", KV_DATA_URL),
    })
}

fn parse_host_port(s: &str) -> (String, u16) {
    if s.trim().is_empty() {
        return (String::new(), 443);
    }
    match s.rsplit_once(':') {
        Some((ip, port)) => (ip.into(), port.parse().unwrap_or(443)),
        None => (s.into(), 443),
    }
}

fn ip_in_rules(ip: &str, rules: &[String]) -> bool {
    if rules.iter().any(|r| r == "0.0.0.0/0" || r == "::/0") {
        return true;
    }
    let Ok(ip_addr) = ip.parse::<IpAddr>() else {
        return false;
    };
    rules.iter().any(|rule| {
        rule.parse::<IpAddr>().is_ok_and(|r| r == ip_addr)
            || rule.parse::<IpNet>().is_ok_and(|n| n.contains(&ip_addr))
    })
}
