//! Produce a non-invasive Mihomo runtime from Tono's redacted diagnostic copy.
//!
//! The output keeps the same admitted nodes, DNS upstreams, groups, and rules, but disables
//! TUN and moves both local listeners off the production ports. It is intended for a real
//! Windows machine where we need to distinguish a runtime/upstream failure from Service/WFP
//! orchestration without touching adapter DNS, routes, or the installed product.

use std::{env, fs, path::PathBuf};

use serde_yaml_ng::{Mapping, Value};

fn string(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn mapping_mut<'a>(root: &'a mut Mapping, key: &str) -> Result<&'a mut Mapping, String> {
    root.get_mut(string(key))
        .and_then(Value::as_mapping_mut)
        .ok_or_else(|| format!("runtime is missing the {key} mapping"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let input = PathBuf::from(
        args.next()
            .ok_or("usage: windows_runtime_dns_probe <input> <output>")?,
    );
    let output = PathBuf::from(
        args.next()
            .ok_or("usage: windows_runtime_dns_probe <input> <output>")?,
    );
    if args.next().is_some() {
        return Err("usage: windows_runtime_dns_probe <input> <output>".into());
    }

    let bytes = fs::read(&input)?;
    let mut runtime: Value = serde_yaml_ng::from_slice(&bytes)?;
    let root = runtime
        .as_mapping_mut()
        .ok_or("runtime root must be a YAML mapping")?;
    root.insert(string("external-controller"), string("127.0.0.1:19090"));
    // The diagnostic copy is already redacted. Assert that invariant instead of ever copying a
    // live controller credential into a probe artifact.
    let secret = root
        .get(string("secret"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !secret.is_empty() {
        return Err("refusing to copy a runtime whose controller secret is not redacted".into());
    }

    mapping_mut(root, "dns")?.insert(string("listen"), string("127.0.0.1:5353"));
    mapping_mut(root, "tun")?.insert(string("enable"), Value::Bool(false));

    fs::write(output, serde_yaml_ng::to_string(&runtime)?)?;
    println!(
        "probe runtime written (TUN disabled, DNS 127.0.0.1:5353, controller 127.0.0.1:19090)"
    );
    Ok(())
}
