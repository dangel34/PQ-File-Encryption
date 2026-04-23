fn main() {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("pqfile — Quantum-Resistant File Encryption")
            .with_inner_size([680.0, 340.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "pqfile",
        options,
        Box::new(|_cc| Ok(Box::new(pqfile_gui::PqfileApp::default()))),
    )
    .unwrap();
}
