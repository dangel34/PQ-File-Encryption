use crate::colors::{
    c_accent, c_chrome, c_green, c_overlay, c_red, c_subtext, c_surface0, c_surface1, c_text,
};
use crate::types::{BatchPending, FileInput, OpStatus, Pending, PickedFile};
use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke, Vec2};
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

pub(crate) fn tab_btn(
    ui: &mut egui::Ui,
    current: &mut crate::types::Tab,
    target: crate::types::Tab,
    label: &str,
    dark: bool,
) {
    let active = *current == target;
    // Active-state text is `c_text`, not `c_accent`: accent-on-surface1 only
    // reaches ~2.7:1 contrast in light mode (well under WCAG AA's 4.5:1),
    // making the *selected* tab label harder to read than the unselected
    // ones. The accent color still marks "active" via the underline below.
    let text_color = if active {
        c_text(dark)
    } else {
        c_subtext(dark)
    };
    let fill = if active {
        c_surface1(dark)
    } else {
        Color32::TRANSPARENT
    };
    let resp = ui.add(
        egui::Button::new(RichText::new(label).size(13.0).color(text_color))
            .fill(fill)
            .stroke(Stroke::NONE),
    );
    if active {
        let r = resp.rect;
        ui.painter().line_segment(
            [
                egui::pos2(r.left() + 4.0, r.bottom()),
                egui::pos2(r.right() - 4.0, r.bottom()),
            ],
            Stroke::new(2.0, c_accent(dark)),
        );
    }
    if resp.clicked() {
        *current = target;
    }
}

/// Renders the "More Tools" overflow button: a dropdown menu holding the
/// specialized/advanced tabs (Sign, Sign & Encrypt, Archive, Shamir, Health
/// Check, Clipboard) so the primary nav row stays short for new users while
/// every feature remains one click away.
pub(crate) fn advanced_tabs_menu(ui: &mut egui::Ui, current: &mut crate::types::Tab, dark: bool) {
    use crate::types::{tab_label, ADVANCED_TABS};

    let active = ADVANCED_TABS.contains(current);
    // See the matching comment in `tab_btn`: accent-on-surface1 fails contrast
    // in light mode, so the active state uses `c_text` with the accent
    // underline as the "you are here" marker instead.
    let text_color = if active {
        c_text(dark)
    } else {
        c_subtext(dark)
    };
    let fill = if active {
        c_surface1(dark)
    } else {
        Color32::TRANSPARENT
    };
    let btn = egui::Button::new(RichText::new("☰ More Tools").size(13.0).color(text_color))
        .fill(fill)
        .stroke(Stroke::NONE);
    let (response, _) = egui::containers::menu::MenuButton::from_button(btn).ui(ui, |ui| {
        for tab in ADVANCED_TABS {
            if ui
                .selectable_label(*current == tab, tab_label(tab))
                .clicked()
            {
                *current = tab;
                ui.close();
            }
        }
    });
    if active {
        let r = response.rect;
        ui.painter().line_segment(
            [
                egui::pos2(r.left() + 4.0, r.bottom()),
                egui::pos2(r.right() - 4.0, r.bottom()),
            ],
            Stroke::new(2.0, c_accent(dark)),
        );
    }
}

/// Renders a tab heading with a "Learn more..." button on the right.
/// Returns `true` if the button was clicked this frame.
pub(crate) fn tab_heading_help(ui: &mut egui::Ui, text: &str, dark: bool) -> bool {
    let mut clicked = false;
    ui.horizontal(|ui| {
        ui.label(RichText::new(text).size(18.0).strong().color(c_text(dark)));
        ui.add_space(8.0);
        if ui
            .add(
                egui::Button::new(
                    RichText::new("Learn more...")
                        .size(12.0)
                        .color(c_subtext(dark)),
                )
                .fill(c_surface0(dark))
                .min_size(egui::vec2(0.0, 22.0)),
            )
            .clicked()
        {
            clicked = true;
        }
    });
    ui.add_space(4.0);
    clicked
}

pub(crate) fn section_label(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(3.0, 11.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(r, CornerRadius::same(1), c_accent(dark));
        ui.add_space(4.0);
        ui.label(
            RichText::new(text)
                .size(10.5)
                .color(c_subtext(dark))
                .strong(),
        );
    });
    ui.add_space(3.0);
}

pub(crate) fn card(
    ui: &mut egui::Ui,
    fill: Color32,
    border: Color32,
    content: impl FnOnce(&mut egui::Ui),
) {
    egui::Frame::NONE
        .fill(fill)
        .stroke(Stroke::new(1.0, border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .outer_margin(Margin::ZERO)
        .show(ui, content);
}

pub(crate) fn setting_toggle(
    ui: &mut egui::Ui,
    val: &mut bool,
    label: &str,
    desc: &str,
    dark: bool,
) {
    let row_w = ui.available_width();
    ui.allocate_ui(egui::vec2(row_w, 40.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new(label).size(13.0).color(c_text(dark)));
                ui.label(RichText::new(desc).size(11.5).color(c_subtext(dark)));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                toggle_switch(ui, val, label, dark);
            });
        });
    });
}

/// `label` is not painted here (the caller already renders it as visible
/// text) - it exists only so a screen reader announces this hand-painted
/// switch as e.g. "Dark mode, checkbox, checked" instead of an unlabeled
/// clickable region. `ui.allocate_exact_size(_, Sense::click())` already
/// makes the rect focusable and keyboard-activatable (Space/Enter) for free
/// (`Sense::click()` implies `Sense::FOCUSABLE`); only the accessible
/// name/role/state were missing before this.
fn toggle_switch(ui: &mut egui::Ui, on: &mut bool, label: &str, dark: bool) -> egui::Response {
    let size = Vec2::new(36.0, 20.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), *on, label)
    });
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool(response.id, *on);
        let off_col = c_surface1(dark);
        let on_col = c_accent(dark);
        let track = Color32::from_rgba_premultiplied(
            lerp_u8(off_col.r(), on_col.r(), t),
            lerp_u8(off_col.g(), on_col.g(), t),
            lerp_u8(off_col.b(), on_col.b(), t),
            255,
        );
        let r = rect.height() / 2.0;
        ui.painter().rect_filled(rect, CornerRadius::from(r), track);
        let knob_x = rect.left() + r + t * (rect.width() - 2.0 * r);
        ui.painter()
            .circle_filled(egui::pos2(knob_x, rect.center().y), r - 2.0, Color32::WHITE);
    }
    response
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t) as u8
}

pub(crate) fn kv_row(ui: &mut egui::Ui, key: &str, value: &str, dark: bool) {
    ui.columns(2, |cols| {
        cols[0].label(RichText::new(key).size(12.5).color(c_subtext(dark)));
        cols[1].with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
            ui.add(egui::Label::new(RichText::new(value).size(12.5).color(c_text(dark))).wrap());
        });
    });
}

/// Shows a subtle "Algorithm: …" hint below a signing/verifying key file row
/// once a key is loaded, so users can tell ML-DSA-65 and SLH-DSA keys apart.
/// Silently shows nothing for unloaded rows or non-signature PEMs.
pub(crate) fn sig_algorithm_hint(ui: &mut egui::Ui, pem: Option<&str>, dark: bool) {
    let Some(pem) = pem else { return };
    let alg = if pem.contains("SLH-DSA-SHAKE-192F") {
        "SLH-DSA-SHAKE-192f  (FIPS 205, hash-based)"
    } else if pem.contains("ML-DSA-65") {
        "ML-DSA-65  (FIPS 204)"
    } else {
        return;
    };
    ui.add_space(2.0);
    ui.label(
        RichText::new(format!("Algorithm: {alg}"))
            .size(11.5)
            .color(c_subtext(dark)),
    );
}

pub(crate) fn bullet(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.horizontal(|ui| {
        ui.label(RichText::new("·").size(13.0).color(c_accent(dark)));
        ui.label(RichText::new(text).size(12.5).color(c_subtext(dark)));
    });
}

pub(crate) fn file_row(
    ui: &mut egui::Ui,
    label: &str,
    slot: &mut FileInput,
    filter_name: &'static str,
    filter_exts: &'static [&'static str],
    dark: bool,
) {
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 26.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(label).size(13.0).color(c_subtext(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(
                        egui::Button::new(RichText::new("Browse…").size(13.0).color(c_text(dark)))
                            .fill(c_surface0(dark)),
                    )
                    .clicked()
                {
                    pick_file(
                        std::sync::Arc::clone(&slot.pending),
                        filter_name,
                        filter_exts,
                    );
                }
                let display = if slot.loaded() {
                    RichText::new(&slot.name).size(13.0).color(c_text(dark))
                } else {
                    RichText::new("No file chosen")
                        .size(13.0)
                        .color(c_overlay(dark))
                };
                ui.label(display);
            });
        });
    });
}

pub(crate) fn pick_file(
    pending: Pending,
    filter_name: &'static str,
    filter_exts: &'static [&'static str],
) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        let mut d = rfd::FileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(path) = d.pick_file() {
            if let Ok(data) = std::fs::read(&path) {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                *pending.lock().unwrap() = Some(PickedFile {
                    name,
                    data,
                    path: Some(path),
                    error: None,
                });
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        let mut d = rfd::AsyncFileDialog::new();
        if !filter_exts.is_empty() {
            d = d.add_filter(filter_name, filter_exts);
        }
        if let Some(file) = d.pick_file().await {
            let name = file.file_name();
            let data = file.read().await;
            *pending.lock().unwrap() = Some(PickedFile {
                name,
                data,
                path: None,
                error: None,
            });
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn read_paths_into_batch(paths: Vec<std::path::PathBuf>) -> Vec<PickedFile> {
    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            match std::fs::read(&path) {
                Ok(data) => PickedFile {
                    name,
                    data,
                    path: Some(path),
                    error: None,
                },
                Err(e) => PickedFile {
                    name,
                    data: Vec::new(),
                    path: Some(path),
                    error: Some(e.to_string()),
                },
            }
        })
        .collect()
}

pub(crate) fn pick_files(pending: BatchPending) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            let batch = read_paths_into_batch(paths);
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Some(files) = rfd::AsyncFileDialog::new().pick_files().await {
            let mut batch: Vec<PickedFile> = Vec::new();
            for file in files {
                let name = file.file_name();
                let data = file.read().await;
                batch.push(PickedFile {
                    name,
                    data,
                    path: None,
                    error: None,
                });
            }
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });
}

/// Opens a multi-file picker filtered to `.pqf` files.
pub(crate) fn pick_pqf_files(pending: BatchPending) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        if let Some(paths) = rfd::FileDialog::new()
            .add_filter("PQF encrypted files", &["pqf"])
            .pick_files()
        {
            let batch = read_paths_into_batch(paths);
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    wasm_bindgen_futures::spawn_local(async move {
        if let Some(files) = rfd::AsyncFileDialog::new()
            .add_filter("PQF encrypted files", &["pqf"])
            .pick_files()
            .await
        {
            let mut batch: Vec<PickedFile> = Vec::new();
            for file in files {
                let name = file.file_name();
                let data = file.read().await;
                batch.push(PickedFile {
                    name,
                    data,
                    path: None,
                    error: None,
                });
            }
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });
}

/// Opens a folder picker and recursively collects every `.pqf` file inside it.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn pick_folder_pqf(pending: BatchPending) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        if let Some(root) = rfd::FileDialog::new()
            .set_title("Select folder to decrypt")
            .pick_folder()
        {
            let mut batch: Vec<PickedFile> = Vec::new();
            walk_dir_pqf(&root, &root, &mut batch);
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    let _ = pending;
}

#[cfg(not(target_arch = "wasm32"))]
fn walk_dir_pqf(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<PickedFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir_pqf(root, &path, out);
        } else if path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("pqf"))
            .unwrap_or(false)
        {
            if let Ok(data) = std::fs::read(&path) {
                let name = path
                    .strip_prefix(root)
                    .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                    .unwrap_or_else(|_| {
                        path.file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default()
                    });
                out.push(PickedFile {
                    name,
                    data,
                    path: Some(path),
                    error: None,
                });
            }
        }
    }
}

/// Opens a folder picker and recursively collects every file inside it.
/// Each file's `name` is its path relative to the chosen folder (e.g. `subdir/photo.jpg`),
/// so the folder hierarchy is preserved when writing output files.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn pick_folder_files(pending: BatchPending) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        if let Some(root) = rfd::FileDialog::new()
            .set_title("Select folder to encrypt")
            .pick_folder()
        {
            let mut batch: Vec<PickedFile> = Vec::new();
            walk_dir_recursive(&root, &root, &mut batch);
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });

    #[cfg(target_arch = "wasm32")]
    let _ = pending; // folder picking not available in browsers
}

/// Recursively walks `dir`, collecting all files relative to `root`.
#[cfg(not(target_arch = "wasm32"))]
fn walk_dir_recursive(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<PickedFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir_recursive(root, &path, out);
        } else if let Ok(data) = std::fs::read(&path) {
            // Use the relative path as the display name so `subdir/file.txt` is
            // distinguishable from a top-level `file.txt`.
            let name = path
                .strip_prefix(root)
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| {
                    path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                });
            out.push(PickedFile {
                name,
                data,
                path: Some(path),
                error: None,
            });
        }
    }
}

/// A single-row passphrase input with a show/hide toggle (eye icon).
/// Returns `true` if the user pressed Enter while the field had focus (submit signal).
pub(crate) fn passphrase_row(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut Zeroizing<String>,
    visible: &mut bool,
    hint: &str,
    dark: bool,
) -> bool {
    let mut submitted = false;
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 26.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(label).size(13.0).color(c_subtext(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let toggle_label = if *visible { "hide" } else { "👁 show" };
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new(toggle_label)
                                .size(11.0)
                                .color(c_subtext(dark)),
                        )
                        .fill(c_surface0(dark))
                        .min_size(egui::vec2(42.0, 22.0)),
                    )
                    .on_hover_text(if *visible {
                        "Hide passphrase"
                    } else {
                        "Show passphrase"
                    })
                    .clicked()
                {
                    *visible = !*visible;
                }
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut **value)
                        .password(!*visible)
                        .hint_text(hint)
                        .font(egui::TextStyle::Body)
                        .desired_width(ui.available_width()),
                );
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    submitted = true;
                }
            });
        });
    });
    submitted
}

/// Opens the containing folder in the OS file manager.
#[cfg(not(target_arch = "wasm32"))]
fn reveal_in_explorer(path: &str) {
    use std::path::Path;
    let p = Path::new(path);
    let dir = if p.is_dir() {
        p.to_owned()
    } else {
        p.parent()
            .map(|d| d.to_owned())
            .unwrap_or_else(|| p.to_owned())
    };
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("explorer").arg(dir).spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(dir).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
    }
}

/// Computes the native output path for a single-file save-result operation
/// whose default location sits next to `input_path` (transformed by
/// `sibling_name`, e.g. adding or stripping a `.pqf` extension) rather than
/// in the current directory, and is relocated into `output_dir` (if set),
/// preserving only the filename. Falls back to `out_name` in the current
/// directory when `input_path` is `None` (e.g. a drag-and-drop file with no
/// path on wasm). Shared by every native single-file operation whose output
/// belongs next to its input: signcrypt, signdecrypt, seal, unseal.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn resolve_sibling_output_path(
    input_path: Option<&std::path::Path>,
    out_name: &str,
    output_dir: &str,
    sibling_name: impl FnOnce(&std::path::Path) -> std::path::PathBuf,
) -> std::path::PathBuf {
    let base = input_path
        .map(sibling_name)
        .unwrap_or_else(|| std::path::PathBuf::from(out_name));
    if output_dir.is_empty() {
        base
    } else {
        std::path::PathBuf::from(output_dir).join(base.file_name().unwrap_or_default())
    }
}

/// Shows a "Reveal" button that opens `output_path`'s containing folder,
/// only once `status` is `OpStatus::Ok`. Shared by every native single-file
/// operation that offers to reveal its output: signdecrypt, seal, unseal.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn reveal_button_if_ok(
    ui: &mut egui::Ui,
    status: &OpStatus,
    output_path: &Option<String>,
    dark: bool,
) {
    if !matches!(status, OpStatus::Ok(_)) {
        return;
    }
    let Some(path) = output_path else {
        return;
    };
    ui.add_space(4.0);
    if ui
        .add(
            egui::Button::new(RichText::new("📂  Reveal").size(12.0).color(c_text(dark)))
                .fill(c_surface0(dark)),
        )
        .clicked()
    {
        reveal_in_explorer(path);
    }
}

/// Writes `data` to `path` atomically via a temp file in the same directory,
/// synced and renamed into place, so a crash or full disk mid-write can never
/// leave `path` truncated or corrupted (mirrors the CLI's `AtomicOutput`).
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut tmp_name = path.file_name().unwrap_or_default().to_owned();
    tmp_name.push(format!(".{pid}-{ts}.tmp"));
    let tmp = path.with_file_name(tmp_name);
    let write_result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()
    })();
    match write_result {
        Ok(()) => std::fs::rename(&tmp, path),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

pub(crate) fn save_result(
    filename: &str,
    data: &[u8],
    native_path: Option<std::path::PathBuf>,
    confirm_overwrite: bool,
) -> OpStatus {
    #[cfg(not(target_arch = "wasm32"))]
    {
        let path = native_path.unwrap_or_else(|| std::path::PathBuf::from(filename));
        if confirm_overwrite && path.exists() {
            return OpStatus::Err(format!(
                "Output already exists: {}. Disable overwrite protection in Settings.",
                path.display()
            ));
        }
        // Ensure the parent directory exists (needed when encrypting a folder
        // with subdirectories and an output_dir is set).
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    return OpStatus::Err(format!("Could not create output directory: {e}"));
                }
            }
        }
        match atomic_write(&path, data) {
            Ok(()) => OpStatus::Ok(format!("Saved ->  {}", path.display())),
            Err(e) => OpStatus::Err(e.to_string()),
        }
    }
    #[cfg(target_arch = "wasm32")]
    {
        let _ = (native_path, confirm_overwrite);
        download_bytes(filename, data);
        OpStatus::Ok(format!("Downloaded: {filename}"))
    }
}

/// Saves `data` via [`save_result`], then - if `fec` is set - also generates
/// and saves a Reed-Solomon forward-error-correction sidecar (`<filename>.fec`)
/// computed over `data`. Mirrors the CLI's `encrypt --fec` post-pass, adapted
/// to the GUI's in-memory result flow: no need to re-read a finished file
/// back off disk here, since `data` already holds the exact ciphertext bytes.
#[cfg(feature = "fec")]
pub(crate) fn save_result_with_fec(
    filename: &str,
    data: &[u8],
    native_path: Option<std::path::PathBuf>,
    confirm_overwrite: bool,
    fec: bool,
) -> OpStatus {
    let status = save_result(filename, data, native_path.clone(), confirm_overwrite);
    if !fec || !matches!(status, OpStatus::Ok(_)) {
        return status;
    }
    match pqfile::fec::generate_sidecar(&mut &data[..]) {
        Ok(sidecar) => {
            let fec_name = format!("{filename}.fec");
            let fec_path = native_path.map(|p| {
                let mut s = p.into_os_string();
                s.push(".fec");
                std::path::PathBuf::from(s)
            });
            // The sidecar write never needs its own overwrite confirmation -
            // the main file's confirmation already covered this operation.
            match save_result(&fec_name, &sidecar, fec_path, false) {
                OpStatus::Ok(_) => status,
                other => OpStatus::Err(format!(
                    "encrypted successfully, but writing the FEC sidecar failed: {other:?}"
                )),
            }
        }
        Err(e) => OpStatus::Err(format!(
            "encrypted successfully, but generating the FEC sidecar failed: {e}"
        )),
    }
}

#[cfg(not(feature = "fec"))]
pub(crate) fn save_result_with_fec(
    filename: &str,
    data: &[u8],
    native_path: Option<std::path::PathBuf>,
    confirm_overwrite: bool,
    _fec: bool,
) -> OpStatus {
    save_result(filename, data, native_path, confirm_overwrite)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn download_bytes(filename: &str, data: &[u8]) {
    if let Err(e) = try_download_bytes(filename, data) {
        web_sys::console::error_1(&e);
    }
}

#[cfg(target_arch = "wasm32")]
fn try_download_bytes(filename: &str, data: &[u8]) -> Result<(), JsValue> {
    use wasm_bindgen::JsCast;
    let len = u32::try_from(data.len())
        .map_err(|_| JsValue::from_str("file too large to download in browser"))?;
    let arr = js_sys::Uint8Array::new_with_length(len);
    arr.copy_from(data);
    let blob = web_sys::Blob::new_with_u8_array_sequence(&js_sys::Array::of1(&arr))?;
    let url = web_sys::Url::create_object_url_with_blob(&blob)?;
    let result = (|| -> Result<(), JsValue> {
        let window = web_sys::window().ok_or_else(|| JsValue::from_str("no window"))?;
        let document = window
            .document()
            .ok_or_else(|| JsValue::from_str("no document"))?;
        let body = document
            .body()
            .ok_or_else(|| JsValue::from_str("no body"))?;
        let a: web_sys::HtmlAnchorElement = document.create_element("a")?.dyn_into()?;
        a.set_href(&url);
        a.set_download(filename);
        body.append_child(&a)?;
        a.click();
        body.remove_child(&a)?;
        Ok(())
    })();
    // Always revoke the object URL, even if DOM operations failed.
    let _ = web_sys::Url::revoke_object_url(&url);
    result
}

/// Wraps `content` in a `ScrollArea` capped at `max_h` pixels.
/// When the content overflows, paints a fade gradient at the bottom of the
/// scroll area to signal that more items exist below.
pub(crate) fn scrollable_list<R>(
    ui: &mut egui::Ui,
    id_salt: &str,
    max_h: f32,
    card_fill: egui::Color32,
    content: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let output = egui::ScrollArea::vertical()
        .id_salt(id_salt)
        .max_height(max_h)
        .auto_shrink([false, true])
        .show(ui, content);

    let overflows = output.content_size.y > output.inner_rect.height() + 1.0;
    if overflows {
        let r = output.inner_rect;
        let grad_h = 22.0_f32;
        // Paint a mesh gradient: transparent → card_fill from (bottom-grad_h) → bottom.
        let mut mesh = egui::epaint::Mesh::default();
        let transp =
            egui::Color32::from_rgba_premultiplied(card_fill.r(), card_fill.g(), card_fill.b(), 0);
        let opaque = egui::Color32::from_rgba_premultiplied(
            card_fill.r(),
            card_fill.g(),
            card_fill.b(),
            220,
        );
        let y0 = r.bottom() - grad_h;
        let y1 = r.bottom();
        let v = mesh.vertices.len() as u32;
        mesh.colored_vertex(egui::pos2(r.left(), y0), transp);
        mesh.colored_vertex(egui::pos2(r.right(), y0), transp);
        mesh.colored_vertex(egui::pos2(r.right(), y1), opaque);
        mesh.colored_vertex(egui::pos2(r.left(), y1), opaque);
        mesh.indices
            .extend_from_slice(&[v, v + 1, v + 2, v, v + 2, v + 3]);
        ui.painter().add(egui::Shape::mesh(mesh));
    }

    output.inner
}

/// Pill-style segmented control. `options` is a slice of `(label, value)` pairs.
/// Sets `*current` to the clicked option's value.
pub(crate) fn seg_tabs<T: PartialEq + Clone>(
    ui: &mut egui::Ui,
    current: &mut T,
    options: &[(&str, T)],
    dark: bool,
) {
    use crate::colors::{c_surface0, c_surface1};
    egui::Frame::NONE
        .fill(c_surface0(dark))
        .corner_radius(egui::CornerRadius::same(7))
        .inner_margin(egui::Margin::same(2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 2.0;
                for (label, value) in options {
                    let active = current == value;
                    // `c_text`, not `c_accent`: accent-on-surface1 only reaches
                    // ~2.7:1 contrast in light mode. The pill's surface1 fill
                    // is itself a sufficient "selected" indicator.
                    let text_col = if active {
                        c_text(dark)
                    } else {
                        c_subtext(dark)
                    };
                    let fill = if active {
                        c_surface1(dark)
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(*label).size(12.5).color(text_col))
                                .fill(fill)
                                .stroke(egui::Stroke::NONE)
                                .corner_radius(egui::CornerRadius::same(5)),
                        )
                        .clicked()
                    {
                        *current = value.clone();
                    }
                }
            });
        });
    ui.add_space(10.0);
}

/// Small clipboard-copy button. Shows "⎘" and copies `text` on click.
/// Returns `true` if clicked this frame.
///
/// The visible glyph alone is not a useful accessible name (a screen reader
/// has no reliable pronunciation for "⎘"), and `on_hover_text` is a
/// mouse-only tooltip that AccessKit never sees - so the accessible name is
/// set explicitly via `widget_info` rather than left to default to the
/// button's own text content.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn copy_text_btn(ui: &mut egui::Ui, text: &str, dark: bool) -> bool {
    let enabled = ui.is_enabled();
    let response = ui
        .add(
            egui::Button::new(RichText::new("⎘").size(11.0).color(c_subtext(dark)))
                .fill(egui::Color32::TRANSPARENT)
                .stroke(egui::Stroke::NONE)
                .min_size(egui::vec2(20.0, 20.0)),
        )
        .on_hover_text("Copy to clipboard");
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, "Copy to clipboard")
    });
    response
        .clicked()
        .then(|| {
            ui.ctx().copy_text(text.to_owned());
        })
        .is_some()
}

/// Shows a primary action button (bold label, accent fill) that's
/// `add_enabled` on `ready`, and runs `action` when it's clicked, when
/// `pp_submitted` is true (an Enter keypress in a passphrase field further up
/// the form), or on a global Cmd/Ctrl+Enter - whichever fires first. Shared
/// by every tab whose primary action is a single big styled button with this
/// three-way trigger.
pub(crate) fn action_button(
    ui: &mut egui::Ui,
    label: &str,
    min_width: f32,
    ready: bool,
    pp_submitted: bool,
    dark: bool,
    action: impl FnOnce(),
) {
    if ui
        .add_enabled(
            ready,
            egui::Button::new(
                RichText::new(label)
                    .size(14.0)
                    .color(c_chrome(dark))
                    .strong(),
            )
            .fill(c_accent(dark))
            .min_size(Vec2::new(min_width, 32.0)),
        )
        .clicked()
        || (ready
            && (pp_submitted
                || ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter))))
    {
        action();
    }
}

pub(crate) fn show_status(ui: &mut egui::Ui, status: &OpStatus, dark: bool) {
    let (msg, color) = match status {
        OpStatus::None => return,
        OpStatus::Ok(m) if m.is_empty() => return,
        OpStatus::Ok(m) => (m.as_str(), c_green(dark)),
        OpStatus::Err(m) => (m.as_str(), c_red(dark)),
    };
    ui.add_space(8.0);
    egui::Frame::NONE
        .fill(Color32::from_rgba_premultiplied(
            color.r(),
            color.g(),
            color.b(),
            30,
        ))
        .stroke(Stroke::new(
            1.0,
            Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 100),
        ))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(RichText::new(msg).size(13.0).color(color));
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs `add_contents` inside a fresh, AccessKit-enabled `egui::Context`
    /// for one pass and returns every resulting AccessKit node's role and
    /// label. This is the automated accessibility harness this crate didn't
    /// have before: it lets a test assert that a widget produces a real,
    /// correctly-labeled AccessKit node - not just that it renders without
    /// panicking. `egui` always depends on `accesskit` (re-exported as
    /// `egui::accesskit`) regardless of the `eframe`-level `accesskit`
    /// feature, which only gates the winit/platform wiring - so this needs
    /// no new dev-dependency.
    fn accesskit_nodes(
        mut add_contents: impl FnMut(&mut egui::Ui),
    ) -> Vec<(egui::accesskit::Role, Option<String>)> {
        let ctx = egui::Context::default();
        ctx.set_fonts(egui::FontDefinitions::empty());
        ctx.enable_accesskit();
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| add_contents(ui));
        // egui 0.36 panics on drop if a frame's TexturesDelta goes unhandled;
        // this harness never stands up a renderer to apply it, so discard it
        // explicitly instead of paying for one just to satisfy the assert.
        output.textures_delta.clear();
        let update = output
            .platform_output
            .accesskit_update
            .expect("enable_accesskit() must populate an AccessKit tree update");
        update
            .nodes
            .iter()
            .map(|(_, node)| (node.role(), node.label().map(str::to_owned)))
            .collect()
    }

    #[test]
    fn toggle_switch_exposes_a_labeled_checkbox_node() {
        let mut on = false;
        let nodes = accesskit_nodes(|ui| {
            setting_toggle(ui, &mut on, "Dark mode", "Use a dark color scheme", false);
        });
        assert!(
            nodes
                .iter()
                .any(|(role, label)| *role == egui::accesskit::Role::CheckBox
                    && label.as_deref() == Some("Dark mode")),
            "expected a CheckBox node labeled 'Dark mode', got: {nodes:?}"
        );
    }

    #[test]
    fn toggle_switch_label_tracks_state() {
        // The label carries the on/off state via the node's Toggled property,
        // not the label text itself - just confirm the checkbox node's
        // `toggled()` reflects `on` in both positions.
        for on_value in [false, true] {
            let mut on = on_value;
            let ctx = egui::Context::default();
            ctx.set_fonts(egui::FontDefinitions::empty());
            ctx.enable_accesskit();
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                setting_toggle(ui, &mut on, "Auto-clear", "desc", false);
            });
            output.textures_delta.clear();
            let update = output.platform_output.accesskit_update.unwrap();
            let node = update
                .nodes
                .iter()
                .find(|(_, n)| n.role() == egui::accesskit::Role::CheckBox)
                .map(|(_, n)| n)
                .expect("checkbox node must exist");
            let expected = if on_value {
                egui::accesskit::Toggled::True
            } else {
                egui::accesskit::Toggled::False
            };
            assert_eq!(node.toggled(), Some(expected));
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn copy_text_btn_exposes_a_labeled_button_node() {
        let nodes = accesskit_nodes(|ui| {
            copy_text_btn(ui, "some secret text", false);
        });
        assert!(
            nodes
                .iter()
                .any(|(role, label)| *role == egui::accesskit::Role::Button
                    && label.as_deref() == Some("Copy to clipboard")),
            "expected a Button node labeled 'Copy to clipboard', got: {nodes:?}"
        );
    }
}
