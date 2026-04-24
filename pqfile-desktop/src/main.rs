#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

fn main() {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("pqfile — Quantum-Resistant File Encryption")
            .with_inner_size([720.0, 520.0])
            .with_min_inner_size([600.0, 400.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "pqfile",
        options,
        Box::new(|cc| Ok(Box::new(pqfile_gui::PqfileApp::new(cc)))),
    )
    .unwrap();
}
