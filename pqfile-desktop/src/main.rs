#![cfg_attr(
    all(target_os = "windows", not(debug_assertions)),
    windows_subsystem = "windows"
)]

fn main() {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
        .expect("failed to load app icon");

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("pqfile - Post-Quantum File Encryption")
            .with_inner_size([1080.0, 780.0])
            .with_min_inner_size([720.0, 520.0])
            .with_icon(icon)
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
