use eframe::egui::Color32;

pub(crate) const D_BASE: Color32 = Color32::from_rgb(30, 30, 46);
pub(crate) const D_MANTLE: Color32 = Color32::from_rgb(24, 24, 37);
pub(crate) const D_SURFACE0: Color32 = Color32::from_rgb(49, 50, 68);
pub(crate) const D_SURFACE1: Color32 = Color32::from_rgb(69, 71, 90);
pub(crate) const D_OVERLAY: Color32 = Color32::from_rgb(108, 112, 134);
pub(crate) const D_SUBTEXT: Color32 = Color32::from_rgb(166, 173, 200);
pub(crate) const D_TEXT: Color32 = Color32::from_rgb(205, 214, 244);
pub(crate) const D_ACCENT: Color32 = Color32::from_rgb(137, 180, 250);
pub(crate) const D_GREEN: Color32 = Color32::from_rgb(166, 227, 161);
pub(crate) const D_RED: Color32 = Color32::from_rgb(243, 139, 168);

pub(crate) const L_BASE: Color32 = Color32::from_rgb(239, 241, 245);
pub(crate) const L_MANTLE: Color32 = Color32::from_rgb(230, 233, 239);
pub(crate) const L_SURFACE0: Color32 = Color32::from_rgb(204, 208, 218);
pub(crate) const L_SURFACE1: Color32 = Color32::from_rgb(188, 192, 204);
pub(crate) const L_OVERLAY: Color32 = Color32::from_rgb(140, 143, 161);
pub(crate) const L_SUBTEXT: Color32 = Color32::from_rgb(108, 111, 133);
pub(crate) const L_TEXT: Color32 = Color32::from_rgb(76, 79, 105);
pub(crate) const L_ACCENT: Color32 = Color32::from_rgb(30, 102, 245);
pub(crate) const L_GREEN: Color32 = Color32::from_rgb(28, 108, 12);
pub(crate) const L_RED: Color32 = Color32::from_rgb(210, 15, 57);

pub(crate) fn c_bg(d: bool) -> Color32 {
    if d {
        D_BASE
    } else {
        L_BASE
    }
}
pub(crate) fn c_chrome(d: bool) -> Color32 {
    if d {
        D_MANTLE
    } else {
        L_MANTLE
    }
}
pub(crate) fn c_card(d: bool) -> Color32 {
    if d {
        D_MANTLE
    } else {
        L_MANTLE
    }
}
pub(crate) fn c_surface0(d: bool) -> Color32 {
    if d {
        D_SURFACE0
    } else {
        L_SURFACE0
    }
}
pub(crate) fn c_surface1(d: bool) -> Color32 {
    if d {
        D_SURFACE1
    } else {
        L_SURFACE1
    }
}
pub(crate) fn c_overlay(d: bool) -> Color32 {
    if d {
        D_OVERLAY
    } else {
        L_OVERLAY
    }
}
pub(crate) fn c_subtext(d: bool) -> Color32 {
    if d {
        D_SUBTEXT
    } else {
        L_SUBTEXT
    }
}
pub(crate) fn c_text(d: bool) -> Color32 {
    if d {
        D_TEXT
    } else {
        L_TEXT
    }
}
pub(crate) fn c_accent(d: bool) -> Color32 {
    if d {
        D_ACCENT
    } else {
        L_ACCENT
    }
}
pub(crate) fn c_green(d: bool) -> Color32 {
    if d {
        D_GREEN
    } else {
        L_GREEN
    }
}
pub(crate) fn c_red(d: bool) -> Color32 {
    if d {
        D_RED
    } else {
        L_RED
    }
}
// Catppuccin Peach (dark) / Yellow (light) - used for warnings.
pub(crate) fn c_yellow(d: bool) -> Color32 {
    if d {
        Color32::from_rgb(250, 179, 135)
    } else {
        Color32::from_rgb(223, 142, 29)
    }
}
