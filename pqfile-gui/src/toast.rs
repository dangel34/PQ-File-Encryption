use crate::colors::{c_chrome, c_green, c_red, c_text};
use eframe::egui::{self, CornerRadius, Margin, RichText, Stroke};
use std::time::Instant;

const LIFETIME_SECS: f32 = 4.0;
const FADE_SECS: f32 = 0.6;

#[derive(Clone, Copy, PartialEq)]
enum ToastKind {
    Success,
    Error,
}

struct Toast {
    kind: ToastKind,
    text: String,
    created: Instant,
}

/// Non-blocking, self-dismissing notifications for background operations
/// (batch jobs, the watchfolder) that can finish while the user is on a
/// different tab and would otherwise have no visible result at all.
/// `Instant`-based rather than egui's frame time, so pushing a toast never
/// needs a `&Context` in hand.
#[derive(Default)]
pub(crate) struct Toasts(Vec<Toast>);

impl Toasts {
    pub(crate) fn success(&mut self, text: impl Into<String>) {
        self.0.push(Toast {
            kind: ToastKind::Success,
            text: text.into(),
            created: Instant::now(),
        });
    }

    pub(crate) fn error(&mut self, text: impl Into<String>) {
        self.0.push(Toast {
            kind: ToastKind::Error,
            text: text.into(),
            created: Instant::now(),
        });
    }

    /// Renders any live toasts, anchored bottom-right, and prunes expired
    /// ones. Call once per frame from the top-level `App::ui`.
    pub(crate) fn show(&mut self, ctx: &egui::Context, dark: bool) {
        self.0
            .retain(|t| t.created.elapsed().as_secs_f32() < LIFETIME_SECS);
        if self.0.is_empty() {
            return;
        }

        egui::Area::new(egui::Id::new("toast_area"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -16.0))
            .order(egui::Order::Foreground)
            .interactable(false)
            .show(ctx, |ui| {
                ui.vertical(|ui| {
                    for t in &self.0 {
                        let age = t.created.elapsed().as_secs_f32();
                        let alpha = if age > LIFETIME_SECS - FADE_SECS {
                            ((LIFETIME_SECS - age) / FADE_SECS).clamp(0.0, 1.0)
                        } else {
                            1.0
                        };
                        let (edge, icon) = match t.kind {
                            ToastKind::Success => (c_green(dark), "\u{2714}"),
                            ToastKind::Error => (c_red(dark), "\u{2716}"),
                        };
                        ui.scope(|ui| {
                            ui.multiply_opacity(alpha);
                            egui::Frame::NONE
                                .fill(c_chrome(dark))
                                .stroke(Stroke::new(1.0, edge))
                                .corner_radius(CornerRadius::same(8))
                                .inner_margin(Margin::symmetric(12, 8))
                                .show(ui, |ui| {
                                    ui.set_max_width(320.0);
                                    ui.horizontal(|ui| {
                                        ui.label(RichText::new(icon).size(15.0).color(edge));
                                        ui.label(
                                            RichText::new(&t.text).size(13.0).color(c_text(dark)),
                                        );
                                    });
                                });
                        });
                        ui.add_space(6.0);
                    }
                });
            });

        // Keeps the fade-out animating and the expiry check above running
        // even when nothing else on screen needs a repaint.
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
