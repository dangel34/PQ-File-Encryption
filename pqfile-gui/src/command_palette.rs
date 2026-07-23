use crate::app::PqfileApp;
use crate::colors::{c_accent, c_bg, c_subtext, c_surface0, c_surface1, c_text};
use crate::types::{tab_label, Tab, ALL_TABS};
use eframe::egui::{self, CornerRadius, RichText, Stroke, Vec2};

impl PqfileApp {
    /// Opens or closes the command palette from the global Ctrl/Cmd+K
    /// shortcut. Declining to open it while another modal (About, Legal,
    /// tab help) is already up avoids stacking overlapping windows.
    pub(crate) fn toggle_command_palette(&mut self, ctx: &egui::Context) {
        let shortcut = egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::K);
        if !ctx.input_mut(|i| i.consume_shortcut(&shortcut)) {
            return;
        }
        if self.command_palette_open {
            self.close_command_palette();
            return;
        }
        if !self.show_about && !self.show_legal && self.help_modal_open.is_none() {
            self.command_palette_open = true;
            self.command_palette_focus_pending = true;
        }
    }

    fn close_command_palette(&mut self) {
        self.command_palette_open = false;
        self.command_palette_query.clear();
        self.command_palette_selected = 0;
    }

    pub(crate) fn show_command_palette(&mut self, ctx: &egui::Context, dark: bool) {
        if !self.command_palette_open {
            return;
        }

        let query_lower = self.command_palette_query.to_lowercase();
        let matches: Vec<Tab> = ALL_TABS
            .into_iter()
            .filter(|t| {
                query_lower.is_empty() || tab_label(*t).to_lowercase().contains(&query_lower)
            })
            .collect();
        if !matches.is_empty() {
            self.command_palette_selected = self.command_palette_selected.min(matches.len() - 1);
        }

        let mut chosen: Option<Tab> = None;
        let mut close = false;
        // Only true on the frame a nav key is pressed, so the list is
        // scrolled to the selection on arrow-key navigation without fighting
        // the user's own mouse-wheel scrolling on every other frame.
        let mut navigated = false;

        ctx.input_mut(|i| {
            if i.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                close = true;
            }
            if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) && !matches.is_empty() {
                self.command_palette_selected =
                    (self.command_palette_selected + 1).min(matches.len() - 1);
                navigated = true;
            }
            if i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                self.command_palette_selected = self.command_palette_selected.saturating_sub(1);
                navigated = true;
            }
            if i.consume_key(egui::Modifiers::NONE, egui::Key::Enter) {
                if let Some(t) = matches.get(self.command_palette_selected) {
                    chosen = Some(*t);
                }
            }
        });

        egui::Window::new("command_palette")
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 90.0))
            .fixed_size([440.0, 0.0])
            .frame(
                egui::Frame::window(&ctx.global_style())
                    .fill(c_bg(dark))
                    .stroke(Stroke::new(2.0, c_accent(dark)))
                    .corner_radius(CornerRadius::same(10)),
            )
            .show(ctx, |ui| {
                ui.add_space(4.0);
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.command_palette_query)
                        .hint_text("Jump to a tab\u{2026}")
                        .desired_width(ui.available_width()),
                );
                // Focused once, right when the palette opens - not every
                // frame, or the text box could never lose focus to anything
                // else while the window is up.
                if self.command_palette_focus_pending {
                    resp.request_focus();
                    self.command_palette_focus_pending = false;
                }
                ui.add_space(6.0);
                ui.separator();
                ui.add_space(4.0);

                if matches.is_empty() {
                    ui.label(
                        RichText::new("No matching tab.")
                            .size(13.0)
                            .color(c_subtext(dark)),
                    );
                }

                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for (i, tab) in matches.iter().enumerate() {
                            let selected = i == self.command_palette_selected;
                            let fill = if selected {
                                c_surface1(dark)
                            } else {
                                c_surface0(dark)
                            };
                            let resp = ui.add(
                                egui::Button::new(
                                    RichText::new(tab_label(*tab))
                                        .size(14.0)
                                        .color(c_text(dark)),
                                )
                                .fill(fill)
                                .stroke(Stroke::NONE)
                                .min_size(Vec2::new(ui.available_width(), 30.0)),
                            );
                            if selected && navigated {
                                resp.scroll_to_me(Some(egui::Align::Center));
                            }
                            if resp.clicked() {
                                chosen = Some(*tab);
                            }
                            ui.add_space(2.0);
                        }
                    });

                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "Up/Down to navigate \u{00b7} Enter to select \u{00b7} Esc to close",
                    )
                    .size(11.0)
                    .color(c_subtext(dark)),
                );
                ui.add_space(4.0);
            });

        if let Some(t) = chosen {
            self.tab = t;
            close = true;
        }
        if close {
            self.close_command_palette();
        }
    }
}
