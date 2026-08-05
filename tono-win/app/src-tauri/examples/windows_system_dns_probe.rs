//! Real-machine probe for the exact Windows DNS API used by Tono.
//!
//! This is deliberately a standalone example instead of a `--features test`
//! test: it compiles the production DNS implementation and does not replace
//! the Windows engine with a success stub.

#[cfg(windows)]
#[path = "../src/tono/windows_dns.rs"]
mod windows_dns;

#[cfg(windows)]
#[tokio::main]
async fn main() {
    let host = std::env::args().nth(1).unwrap_or_else(|| "www.gstatic.com".to_string());
    match windows_dns::query_a(&host, std::time::Duration::from_secs(5)).await {
        Ok(addresses) => println!("{host}: {addresses:?}"),
        Err(error) => {
            eprintln!("{host}: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("windows_system_dns_probe only runs on Windows");
    std::process::exit(2);
}
