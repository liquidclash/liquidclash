use reqwest::blocking::Client;
use reqwest::redirect::Policy;
use std::env;
use std::time::Duration;

fn main() {
    let url = match env::args().nth(1) {
        Some(u) => u,
        None => {
            eprintln!("Usage: clash-fetcher <url>");
            std::process::exit(1);
        }
    };

    // Match Clash Verge Rev's exact reqwest+rustls configuration
    let client = Client::builder()
        .use_rustls_tls()
        .redirect(Policy::limited(10))
        .tcp_keepalive(Duration::from_secs(60))
        .pool_max_idle_per_host(0)
        .pool_idle_timeout(None)
        .no_proxy()
        .user_agent("clash-verge/v2.4.8")
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|e| {
            eprintln!("Failed to build client: {}", e);
            std::process::exit(1);
        });

    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Request failed: {}", e);
            std::process::exit(1);
        }
    };

    // Output subscription-userinfo header if present
    if let Some(info) = response.headers().get("subscription-userinfo") {
        if let Ok(s) = info.to_str() {
            eprintln!("subscription-userinfo: {}", s);
        }
    }

    // Output content-disposition header if present
    if let Some(cd) = response.headers().get("content-disposition") {
        if let Ok(s) = cd.to_str() {
            eprintln!("content-disposition: {}", s);
        }
    }

    // Output profile-update-interval if present
    if let Some(interval) = response.headers().get("profile-update-interval") {
        if let Ok(s) = interval.to_str() {
            eprintln!("profile-update-interval: {}", s);
        }
    }

    let body = match response.text() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Failed to read body: {}", e);
            std::process::exit(1);
        }
    };

    print!("{}", body);
}
