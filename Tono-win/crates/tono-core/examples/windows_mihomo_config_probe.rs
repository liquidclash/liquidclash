//! Emit a credential-free runtime fixture for validation with the pinned
//! Windows Mihomo binary (`verge-mihomo.exe -t -f <output>`).

use std::{net::Ipv4Addr, path::PathBuf};

use tono_core::{
    config::{DirectPlan, build_owned_runtime},
    node::admit_node,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: windows_mihomo_config_probe <output.yaml>")?;
    let fixture = serde_yaml_ng::from_str(
        r#"
name: "Fixture Reality"
type: vless
server: 8.8.8.8
port: 443
uuid: "9e107d9d-372b-4c81-8d2b-3f2d0a1b2c3d"
tls: true
sni: "www.microsoft.com"
flow: xtls-rprx-vision
reality-opts:
  public-key: "0123456789abcdef0123456789abcdef0123456789a"
  short-id: "0123456789abcdef"
"#,
    )?;
    let node = admit_node(&fixture)?;
    let direct = DirectPlan {
        physical_interface: "Ethernet".to_string(),
        hosts: vec![("www.example.com".to_string(), "93.184.216.34".to_string())],
        tcp_wechat_rules: vec![(
            "www.example.com".to_string(),
            Ipv4Addr::new(93, 184, 216, 34),
            443,
        )],
        tcp_web_rules: vec![(
            "www.example.org".to_string(),
            Ipv4Addr::new(93, 184, 216, 35),
            443,
        )],
        udp_wechat_rules: vec![(Ipv4Addr::new(93, 184, 216, 36), 443)],
    };
    let runtime = build_owned_runtime(&[node], "Fixture Reality", "fixture-secret", Some(&direct))?;
    std::fs::write(&output, runtime.yaml())?;
    println!("{}", output.display());
    Ok(())
}
