use eframe::egui::Color32;
use std::sync::atomic::{AtomicU32, Ordering};

/// User-chosen accent color overriding `D_ACCENT`/`L_ACCENT`, packed as
/// `0x00RRGGBB`; `u32::MAX` means "no override, use the theme default". A
/// process-wide atomic rather than app state threaded through every call site,
/// since `c_accent` is called directly (not via `ctx.style()`) from ~100
/// places across every tab.
static ACCENT_OVERRIDE: AtomicU32 = AtomicU32::new(u32::MAX);

/// Sets (or clears, with `None`) the custom accent color applied by every
/// subsequent `c_accent` call, in both dark and light mode alike.
pub(crate) fn set_accent_override(color: Option<Color32>) {
    let packed = match color {
        Some(c) => (u32::from(c.r()) << 16) | (u32::from(c.g()) << 8) | u32::from(c.b()),
        None => u32::MAX,
    };
    ACCENT_OVERRIDE.store(packed, Ordering::Relaxed);
}

pub(crate) const D_BASE: Color32 = Color32::from_rgb(30, 30, 46);
pub(crate) const D_MANTLE: Color32 = Color32::from_rgb(24, 24, 37);
pub(crate) const D_SURFACE0: Color32 = Color32::from_rgb(49, 50, 68);
pub(crate) const D_SURFACE1: Color32 = Color32::from_rgb(69, 71, 90);
// Lightened from Catppuccin Mocha's stock "overlay0" (#6c7086): the stock tone
// only reaches ~3.4:1 contrast against our mantle/base backgrounds (fails WCAG
// AA's 4.5:1 for normal text), and this color is used app-wide as real,
// user-facing text (footer version, file-picker placeholders, hints) rather
// than purely decorative chrome.
pub(crate) const D_OVERLAY: Color32 = Color32::from_rgb(132, 135, 153);
pub(crate) const D_SUBTEXT: Color32 = Color32::from_rgb(166, 173, 200);
pub(crate) const D_TEXT: Color32 = Color32::from_rgb(205, 214, 244);
pub(crate) const D_ACCENT: Color32 = Color32::from_rgb(137, 180, 250);
pub(crate) const D_GREEN: Color32 = Color32::from_rgb(166, 227, 161);
pub(crate) const D_RED: Color32 = Color32::from_rgb(243, 139, 168);

pub(crate) const L_BASE: Color32 = Color32::from_rgb(239, 241, 245);
pub(crate) const L_MANTLE: Color32 = Color32::from_rgb(230, 233, 239);
pub(crate) const L_SURFACE0: Color32 = Color32::from_rgb(204, 208, 218);
pub(crate) const L_SURFACE1: Color32 = Color32::from_rgb(188, 192, 204);
// Darkened from Catppuccin Latte's stock "overlay1" (#8c8fa1): the stock tone
// only reaches ~2.6-2.8:1 contrast against our mantle/base backgrounds (fails
// even WCAG AA's 3:1 floor for large text), and this color is used app-wide
// as real, user-facing text rather than purely decorative chrome.
pub(crate) const L_OVERLAY: Color32 = Color32::from_rgb(102, 104, 118);
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
    let packed = ACCENT_OVERRIDE.load(Ordering::Relaxed);
    if packed != u32::MAX {
        let r = ((packed >> 16) & 0xFF) as u8;
        let g = ((packed >> 8) & 0xFF) as u8;
        let b = (packed & 0xFF) as u8;
        return Color32::from_rgb(r, g, b);
    }
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
        // Darkened from Catppuccin Latte's stock "yellow" (#df8e1d): the stock
        // tone only reaches ~2.1-2.3:1 contrast against our mantle/base
        // backgrounds (warning badges were nearly invisible), well below even
        // WCAG AA's 3:1 floor for large text.
        Color32::from_rgb(145, 92, 19)
    }
}
