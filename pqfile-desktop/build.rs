fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set(
            "FileDescription",
            "pqfile — Quantum-Resistant File Encryption",
        );
        res.set("ProductName", "pqfile");
        res.set("LegalCopyright", "MIT License");
        if let Err(e) = res.compile() {
            eprintln!("cargo:warning=winres failed (icon not embedded): {e}");
        }
    }
}
