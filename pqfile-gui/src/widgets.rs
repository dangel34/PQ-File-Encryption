use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke, Vec2};
use crate::colors::*;
use crate::types::{BatchPending, FileInput, OpStatus, Pending, PickedFile};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsValue;

pub(crate) fn tab_btn(ui: &mut egui::Ui, current: &mut crate::types::Tab, target: crate::types::Tab, label: &str, dark: bool) {
    let active = *current == target;
    let text_color = if active { c_accent(dark) } else { c_subtext(dark) };
    let fill = if active { c_surface1(dark) } else { Color32::TRANSPARENT };
    let resp = ui.add(
        egui::Button::new(RichText::new(label).size(13.0).color(text_color))
            .fill(fill)
            .stroke(Stroke::NONE),
    );
    if active {
        let r = resp.rect;
        ui.painter().line_segment(
            [egui::pos2(r.left() + 4.0, r.bottom()), egui::pos2(r.right() - 4.0, r.bottom())],
            Stroke::new(2.0, c_accent(dark)),
        );
    }
    if resp.clicked() {
        *current = target;
    }
}

pub(crate) fn tab_heading(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.label(RichText::new(text).size(18.0).strong().color(c_text(dark)));
    ui.add_space(4.0);
}

pub(crate) fn section_label(ui: &mut egui::Ui, text: &str, dark: bool) {
    ui.horizontal(|ui| {
        let (r, _) = ui.allocate_exact_size(egui::vec2(3.0, 11.0), egui::Sense::hover());
        ui.painter().rect_filled(r, CornerRadius::same(1), c_accent(dark));
        ui.add_space(4.0);
        ui.label(RichText::new(text).size(10.5).color(c_subtext(dark)).strong());
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
                toggle_switch(ui, val, dark);
            });
        });
    });
}

pub(crate) fn toggle_switch(ui: &mut egui::Ui, on: &mut bool, dark: bool) -> egui::Response {
    let size = Vec2::new(36.0, 20.0);
    let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    if ui.is_rect_visible(rect) {
        let t = ui.ctx().animate_bool(response.id, *on);
        let off_col = c_surface1(dark);
        let on_col  = c_accent(dark);
        let track = Color32::from_rgba_premultiplied(
            lerp_u8(off_col.r(), on_col.r(), t),
            lerp_u8(off_col.g(), on_col.g(), t),
            lerp_u8(off_col.b(), on_col.b(), t),
            255,
        );
        let r = rect.height() / 2.0;
        ui.painter().rect_filled(rect, CornerRadius::from(r), track);
        let knob_x = rect.left() + r + t * (rect.width() - 2.0 * r);
        ui.painter().circle_filled(
            egui::pos2(knob_x, rect.center().y),
            r - 2.0,
            Color32::WHITE,
        );
    }
    response
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    (a as f32 + (b as f32 - a as f32) * t) as u8
}

pub(crate) fn kv_row(ui: &mut egui::Ui, key: &str, value: &str, dark: bool) {
    let w = ui.available_width();
    ui.allocate_ui(egui::vec2(w, 20.0), |ui| {
        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
            ui.label(RichText::new(key).size(12.5).color(c_subtext(dark)));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(value).size(12.5).color(c_text(dark)).monospace());
            });
        });
    });
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
                    pick_file(std::sync::Arc::clone(&slot.pending), filter_name, filter_exts);
                }
                let display = if slot.loaded() {
                    RichText::new(&slot.name).size(13.0).color(c_text(dark))
                } else {
                    RichText::new("No file chosen").size(13.0).color(c_overlay(dark))
                };
                ui.label(display);
            });
        });
    });
}

pub(crate) fn pick_file(pending: Pending, filter_name: &'static str, filter_exts: &'static [&'static str]) {
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
                *pending.lock().unwrap() = Some(PickedFile { name, data, path: Some(path) });
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
            *pending.lock().unwrap() = Some(PickedFile { name, data, path: None });
        }
    });
}

pub(crate) fn pick_files(pending: BatchPending) {
    #[cfg(not(target_arch = "wasm32"))]
    std::thread::spawn(move || {
        if let Some(paths) = rfd::FileDialog::new().pick_files() {
            let mut batch: Vec<PickedFile> = Vec::new();
            for path in paths {
                if let Ok(data) = std::fs::read(&path) {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    batch.push(PickedFile { name, data, path: Some(path) });
                }
            }
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
                batch.push(PickedFile { name, data, path: None });
            }
            if !batch.is_empty() {
                *pending.lock().unwrap() = Some(batch);
            }
        }
    });
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
                "Output already exists: {}  — disable overwrite protection in Settings.",
                path.display()
            ));
        }
        match std::fs::write(&path, data) {
            Ok(()) => OpStatus::Ok(format!("Saved →  {}", path.display())),
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
        let document = window.document().ok_or_else(|| JsValue::from_str("no document"))?;
        let body = document.body().ok_or_else(|| JsValue::from_str("no body"))?;
        let a: web_sys::HtmlAnchorElement =
            document.create_element("a")?.dyn_into()?;
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

pub(crate) fn show_status(ui: &mut egui::Ui, status: &OpStatus, dark: bool) {
    let (msg, color) = match status {
        OpStatus::None => return,
        OpStatus::Ok(m) if m.is_empty() => return,
        OpStatus::Ok(m)  => (m.as_str(), c_green(dark)),
        OpStatus::Err(m) => (m.as_str(), c_red(dark)),
    };
    ui.add_space(8.0);
    egui::Frame::NONE
        .fill(Color32::from_rgba_premultiplied(color.r(), color.g(), color.b(), 30))
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
