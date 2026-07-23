use crate::colors::{
    c_accent, D_BASE, D_MANTLE, D_OVERLAY, D_SUBTEXT, D_SURFACE0, D_SURFACE1, D_TEXT, L_BASE,
    L_MANTLE, L_OVERLAY, L_SUBTEXT, L_SURFACE0, L_SURFACE1, L_TEXT,
};
use eframe::egui::{self, Color32, CornerRadius, Margin, Stroke, Vec2};

pub(crate) fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut v = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    let (base, mantle, surf0, surf1, overlay, subtext, text) = if dark {
        (
            D_BASE, D_MANTLE, D_SURFACE0, D_SURFACE1, D_OVERLAY, D_SUBTEXT, D_TEXT,
        )
    } else {
        (
            L_BASE, L_MANTLE, L_SURFACE0, L_SURFACE1, L_OVERLAY, L_SUBTEXT, L_TEXT,
        )
    };
    // Routed through `c_accent` (not the raw `D_ACCENT`/`L_ACCENT` constants)
    // so a user-chosen custom accent (Settings > Appearance) reaches the
    // widget visuals below too, not just the ~100 direct `c_accent(dark)`
    // call sites across the tabs.
    let accent = c_accent(dark);

    let shadow_alpha = if dark { 80u8 } else { 24u8 };

    v.panel_fill = mantle;
    v.window_fill = base;
    v.override_text_color = Some(text);

    v.widgets.noninteractive.bg_fill = surf0;
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, subtext);
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, surf1);

    v.widgets.inactive.bg_fill = surf0;
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, text);
    v.widgets.inactive.bg_stroke = Stroke::NONE;

    v.widgets.hovered.bg_fill = surf1;
    v.widgets.hovered.fg_stroke = Stroke::new(1.5, accent);
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, accent);
    v.widgets.hovered.expansion = 0.0;

    v.widgets.active.bg_fill = accent;
    v.widgets.active.fg_stroke = Stroke::new(1.5, mantle);

    v.selection.bg_fill = Color32::from_rgba_premultiplied(accent.r(), accent.g(), accent.b(), 55);
    v.selection.stroke = Stroke::new(1.0, accent);

    v.window_corner_radius = CornerRadius::same(8);
    v.window_stroke = Stroke::new(1.0, surf1);
    v.popup_shadow = egui::Shadow {
        offset: [0, 4],
        blur: 16,
        spread: 0,
        color: Color32::from_black_alpha(shadow_alpha),
    };

    let r = CornerRadius::same(6);
    v.widgets.noninteractive.corner_radius = r;
    v.widgets.inactive.corner_radius = r;
    v.widgets.hovered.corner_radius = r;
    v.widgets.active.corner_radius = r;

    let _ = overlay;

    ctx.set_visuals(v);

    let mut style = (*ctx.global_style()).clone();
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style.spacing.window_margin = Margin::same(16);
    ctx.set_global_style(style);
}
