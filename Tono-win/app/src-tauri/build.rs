fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        // Tauri's resource is linked to the app binary, but not to Rust unit-test harnesses.
        // Give every test target its own Common Controls v6 activation context so the loader can
        // resolve TaskDialogIndirect. This used to be gated on the `clippy` feature, which meant
        // ordinary and windows-integration-test harnesses compiled successfully but died before
        // running their first assertion with STATUS_ENTRYPOINT_NOT_FOUND.
        let out_dir = std::env::var_os("OUT_DIR").ok_or_else(|| std::io::Error::other("OUT_DIR is not set"))?;
        let manifest_path = std::path::PathBuf::from(out_dir).join("windows-test-manifest.xml");
        std::fs::write(
            &manifest_path,
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity
        type="win32"
        name="Microsoft.Windows.Common-Controls"
        version="6.0.0.0"
        processorArchitecture="*"
        publicKeyToken="6595b64144ccf1df"
        language="*"
      />
    </dependentAssembly>
  </dependency>
</assembly>
"#,
        )?;
        // Cargo has no link-arg selector for a library's *unit-test harness*
        // (`rustc-link-arg-tests` addresses explicit integration-test targets only), so this
        // must be a crate-wide link argument. `tauri_build` is configured below to leave the
        // manifest out of its resource library; otherwise the app binary receives resource ID 1
        // twice and MSVC fails with CVT1100. Icons/version data still come from Tauri's resource,
        // while this one manifest serves both the app binary and otherwise resource-less tests.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest_path.display());
    }

    #[cfg(feature = "clippy")]
    {
        println!("cargo:warning=Skipping tauri_build during Clippy");
    }

    #[cfg(not(feature = "clippy"))]
    tauri_build::try_build(
        tauri_build::Attributes::new().windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest()),
    )?;

    Ok(())
}
