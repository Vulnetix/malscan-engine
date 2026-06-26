//! The egui application: ecosystem switcher + tabbed per-ecosystem config.
//!
//! Keyboard model (shown in the bottom legend), active unless a text field is
//! focused:
//!
//! - `↑`/`↓` — move the capability selection cursor
//! - `Space`/`Enter` — toggle the selected capability
//! - `←`/`→` — cycle ecosystem (previous / next)
//! - `Tab`/`Shift+Tab` — switch view (Overview / Config JSON)
//! - `A` — toggle all capabilities for the ecosystem
//! - `/` — open the jump box; type a name/slug to live-select, Enter commits, Esc cancels
//!
//! Hotkeys use `consume_key` so they don't also fire egui's defaults (e.g. `Tab`
//! moving widget focus); the block is skipped while a `TextEdit` is focused so
//! typing in the endpoint/jump fields is never stolen.

use std::collections::HashSet;

use eframe::egui::{self, Color32, Key, Modifiers, RichText};

use crate::api;
use crate::config::{self, AppConfig};
use crate::model::{self, Class};

/// Which tab is showing for the selected ecosystem.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Overview,
    ConfigJson,
}

const TABS: [Tab; 2] = [Tab::Overview, Tab::ConfigJson];

/// The result of the last save, shown as a status banner.
struct SaveStatus {
    slug: String,
    ok: bool,
    message: String,
}

pub struct MalscanApp {
    /// Selected ecosystem slug.
    selected: String,
    /// Active tab.
    tab: Tab,
    /// All editable settings.
    config: AppConfig,
    /// Ecosystems with unsaved edits (slugs).
    dirty: HashSet<String>,
    /// Last save outcome.
    status: Option<SaveStatus>,

    // ── Keyboard navigation ──────────────────────────────────────────────────
    /// Cursor into the current ecosystem's supported-capability list.
    selected_cap: usize,
    /// Scroll the selected row into view this frame (set on keyboard moves).
    scroll_to_sel: bool,
    /// The jump-to-ecosystem box is open.
    jump_active: bool,
    /// Text typed into the jump box.
    jump_query: String,
    /// Selection to restore if the jump box is cancelled with `Esc`.
    jump_prev: String,
    /// Request focus for the jump box on the next frame.
    focus_jump: bool,
}

impl MalscanApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            selected: model::ECOSYSTEMS[0].slug.to_string(),
            tab: Tab::Overview,
            // Load the live config files from disk (falls back to defaults).
            config: AppConfig::load(),
            dirty: HashSet::new(),
            status: None,
            selected_cap: 0,
            scroll_to_sel: false,
            jump_active: false,
            jump_query: String::new(),
            jump_prev: String::new(),
            focus_jump: false,
        }
    }
}

impl eframe::App for MalscanApp {
    // eframe 0.34 hands us a root `Ui` (no margin/background); we lay panels out
    // inside it with `show_inside`.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.handle_keys(ui.ctx());
        self.clamp_selection();

        self.top_bar(ui);
        // A distinct fill so the legend reads as a status bar; the default
        // bottom-panel frame matches the window background and would be invisible.
        let bar_fill = ui.visuals().faint_bg_color;
        egui::Panel::bottom("legend")
            .frame(
                egui::Frame::new()
                    .fill(bar_fill)
                    .inner_margin(egui::Margin::symmetric(8, 3)),
            )
            .show_inside(ui, |ui| self.legend(ui));
        egui::CentralPanel::default().show_inside(ui, |ui| match self.tab {
            Tab::Overview => self.overview_tab(ui),
            Tab::ConfigJson => self.config_json_tab(ui),
        });
    }
}

impl MalscanApp {
    // ── Input ────────────────────────────────────────────────────────────────

    /// Translate global hotkeys into state changes. Skipped while a text edit
    /// (the endpoint or jump box) is focused so typing is never stolen — note we
    /// gate on `text_edit_focused`, not "any focus", so a clicked checkbox does
    /// not disable the hotkeys.
    fn handle_keys(&mut self, ctx: &egui::Context) {
        if ctx.text_edit_focused() {
            return;
        }
        let on_overview = self.tab == Tab::Overview;
        ctx.input_mut(|i| {
            // Ecosystem cycling and view switching — available on any tab.
            if i.consume_key(Modifiers::NONE, Key::ArrowRight) {
                self.cycle_ecosystem(1);
            }
            if i.consume_key(Modifiers::NONE, Key::ArrowLeft) {
                self.cycle_ecosystem(-1);
            }
            if i.consume_key(Modifiers::NONE, Key::Tab) {
                self.cycle_tab(1);
            }
            if i.consume_key(Modifiers::SHIFT, Key::Tab) {
                self.cycle_tab(-1);
            }
            if i.consume_key(Modifiers::NONE, Key::Slash) {
                self.open_jump();
            }

            // Capability navigation — only meaningful on the Overview tab.
            if on_overview {
                if i.consume_key(Modifiers::NONE, Key::ArrowDown) {
                    self.move_selection(1);
                }
                if i.consume_key(Modifiers::NONE, Key::ArrowUp) {
                    self.move_selection(-1);
                }
                let toggle = i.consume_key(Modifiers::NONE, Key::Space)
                    || i.consume_key(Modifiers::NONE, Key::Enter);
                if toggle {
                    self.toggle_selected();
                }
                if i.consume_key(Modifiers::NONE, Key::A) {
                    self.toggle_all();
                }
            }
        });
    }

    fn cycle_ecosystem(&mut self, delta: isize) {
        let n = model::ECOSYSTEMS.len() as isize;
        let cur = model::ECOSYSTEMS
            .iter()
            .position(|e| e.slug == self.selected)
            .unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(n) as usize;
        self.selected = model::ECOSYSTEMS[next].slug.to_string();
        self.selected_cap = 0;
        self.scroll_to_sel = true;
    }

    fn cycle_tab(&mut self, delta: isize) {
        let cur = TABS.iter().position(|t| *t == self.tab).unwrap_or(0) as isize;
        let next = (cur + delta).rem_euclid(TABS.len() as isize) as usize;
        self.tab = TABS[next];
    }

    fn move_selection(&mut self, delta: isize) {
        let len = model::capabilities_for(&self.selected).len() as isize;
        if len == 0 {
            return;
        }
        self.selected_cap = (self.selected_cap as isize + delta).rem_euclid(len) as usize;
        self.scroll_to_sel = true;
    }

    /// Flip the capability currently under the cursor.
    fn toggle_selected(&mut self) {
        let caps = model::capabilities_for(&self.selected);
        let Some(cap) = caps.get(self.selected_cap) else {
            return;
        };
        if let Some(cfg) = self.config.ecosystems.get_mut(&self.selected) {
            if let Some(state) = cfg.capabilities.get_mut(cap.key) {
                *state = !*state;
                self.dirty.insert(self.selected.clone());
            }
        }
    }

    /// If every capability is on, turn them all off; otherwise turn them all on.
    fn toggle_all(&mut self) {
        let all_on = self
            .config
            .ecosystems
            .get(&self.selected)
            .map(|c| !c.capabilities.is_empty() && c.enabled_count() == c.capabilities.len())
            .unwrap_or(false);
        self.config.set_all_capabilities(&self.selected, !all_on);
        self.dirty.insert(self.selected.clone());
    }

    fn open_jump(&mut self) {
        self.jump_active = true;
        self.focus_jump = true;
        self.jump_prev = self.selected.clone();
        self.jump_query.clear();
    }

    fn close_jump(&mut self) {
        self.jump_active = false;
        self.jump_query.clear();
        self.focus_jump = false;
    }

    /// Keep the capability cursor within the current ecosystem's list (the count
    /// changes when the ecosystem changes).
    fn clamp_selection(&mut self) {
        let len = model::capabilities_for(&self.selected).len();
        if self.selected_cap >= len {
            self.selected_cap = len.saturating_sub(1);
        }
    }

    // ── Layout ───────────────────────────────────────────────────────────────

    /// Title, ecosystem switcher / jump box, and the tab strip.
    fn top_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("top").show_inside(ui, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("malscan-engine");
                ui.label(RichText::new("frontend").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.jump_active {
                        self.jump_box(ui);
                    } else {
                        self.ecosystem_combo(ui);
                    }
                });
            });

            ui.add_space(2.0);
            ui.horizontal(|ui| {
                self.tab_button(ui, Tab::Overview, "Overview");
                self.tab_button(ui, Tab::ConfigJson, "Config (JSON)");
            });
            ui.add_space(2.0);
        });
    }

    /// The ecosystem switcher dropdown.
    fn ecosystem_combo(&mut self, ui: &mut egui::Ui) {
        let current = model::ecosystem(&self.selected)
            .map(|e| e.name.to_string())
            .unwrap_or_else(|| self.selected.clone());
        egui::ComboBox::from_id_salt("ecosystem-switcher")
            .selected_text(RichText::new(current).strong())
            .show_ui(ui, |ui| {
                for eco in model::ECOSYSTEMS {
                    let label = format!("{}  ({})", eco.name, eco.slug);
                    if ui
                        .selectable_value(&mut self.selected, eco.slug.to_string(), label)
                        .clicked()
                    {
                        self.selected_cap = 0;
                    }
                }
            });
        ui.label("Ecosystem:");
    }

    /// The type-ahead jump box (opened with `/`). Live-selects the best match as
    /// the user types; `Enter` commits, `Esc` restores the prior selection.
    fn jump_box(&mut self, ui: &mut egui::Ui) {
        // Read Esc before the TextEdit can consume it, so cancel is reliable.
        let esc = ui.input(|i| i.key_pressed(Key::Escape));

        let resp = ui.add(
            egui::TextEdit::singleline(&mut self.jump_query)
                .desired_width(200.0)
                .hint_text("type ecosystem — Enter/Esc"),
        );
        if self.focus_jump {
            resp.request_focus();
            self.focus_jump = false;
        }

        // Live type-ahead: select the best match as the query changes.
        if let Some(slug) = model::match_ecosystem(&self.jump_query) {
            if slug != self.selected {
                self.selected = slug.to_string();
                self.selected_cap = 0;
                self.scroll_to_sel = true;
            }
        }

        if esc {
            self.selected = self.jump_prev.clone();
            self.close_jump();
        } else if resp.lost_focus() {
            // Enter or click-away commits the current (live-selected) ecosystem.
            self.close_jump();
        }
        ui.label("Jump:");
    }

    fn tab_button(&mut self, ui: &mut egui::Ui, tab: Tab, label: &str) {
        let selected = self.tab == tab;
        let mut text = RichText::new(label);
        if selected {
            text = text.strong();
        }
        if ui.selectable_label(selected, text).clicked() {
            self.tab = tab;
        }
    }

    /// Bottom legend describing the keyboard model.
    fn legend(&self, ui: &mut egui::Ui) {
        ui.add_space(3.0);
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            key_hint(ui, "↑/↓", "select");
            key_hint(ui, "Space", "toggle");
            key_hint(ui, "←/→", "ecosystem");
            key_hint(ui, "Tab", "view");
            key_hint(ui, "A", "toggle all");
            key_hint(ui, "/", "jump");
        });
        ui.add_space(3.0);
    }

    /// Overview tab: registry endpoint + capability toggles for the ecosystem.
    fn overview_tab(&mut self, ui: &mut egui::Ui) {
        let slug = self.selected.clone();
        let eco_name = model::ecosystem(&slug).map(|e| e.name).unwrap_or(&slug);

        // Deferred actions, applied after the mutable-borrow scope below.
        let mut changed = false;
        let mut do_save = false;
        let mut do_reset = false;
        let mut set_all: Option<bool> = None;
        let mut clicked_idx: Option<usize> = None;

        // Copied out so the grid closure doesn't need to borrow `self`.
        let sel = self.selected_cap;
        let scroll = self.scroll_to_sel;
        let accent = ui.visuals().selection.bg_fill;

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add_space(6.0);

            // ── Registry endpoint ────────────────────────────────────────────
            ui.heading("Registry endpoint");
            ui.label(
                RichText::new(format!(
                    "Where the engine resolves {eco_name} packages from."
                ))
                .weak(),
            );
            ui.add_space(4.0);

            {
                let cfg = self.config.ecosystems.get_mut(&slug).expect("known slug");
                ui.horizontal(|ui| {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut cfg.registry_endpoint)
                            .desired_width(520.0)
                            .hint_text("https://registry.example.org"),
                    );
                    if resp.changed() {
                        changed = true;
                    }
                    if ui
                        .button("Reset")
                        .on_hover_text("Restore the default endpoint")
                        .clicked()
                    {
                        do_reset = true;
                    }
                });
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);

            // ── Capabilities ─────────────────────────────────────────────────
            let supported = model::capabilities_for(&slug);
            let enabled = self.config.ecosystems[&slug].enabled_count();
            ui.horizontal(|ui| {
                ui.heading("Engine capabilities");
                ui.label(
                    RichText::new(format!(
                        "{enabled}/{} enabled for {eco_name}",
                        supported.len()
                    ))
                    .weak(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Disable all").clicked() {
                        set_all = Some(false);
                    }
                    if ui.small_button("Enable all").clicked() {
                        set_all = Some(true);
                    }
                });
            });
            ui.add_space(4.0);

            {
                let cfg = self.config.ecosystems.get_mut(&slug).expect("known slug");
                egui::Grid::new("capabilities-grid")
                    .num_columns(3)
                    .spacing([12.0, 8.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for (idx, cap) in supported.iter().enumerate() {
                            if let Some(state) = cfg.capabilities.get_mut(cap.key) {
                                let mut label = RichText::new(cap.name);
                                if idx == sel {
                                    label = label
                                        .strong()
                                        .background_color(accent.gamma_multiply(0.45));
                                }
                                let resp = ui.checkbox(state, label).on_hover_text(cap.detail);
                                if resp.changed() {
                                    changed = true;
                                }
                                if resp.clicked() {
                                    clicked_idx = Some(idx);
                                }
                                if idx == sel && scroll {
                                    resp.scroll_to_me(Some(egui::Align::Center));
                                }
                            }
                            class_chip(ui, cap.class);
                            ui.label(RichText::new(cap.engine_ref).monospace().weak().size(11.0));
                            ui.end_row();
                        }
                    });
            }

            ui.add_space(10.0);
            ui.separator();
            ui.add_space(6.0);

            // ── Save ─────────────────────────────────────────────────────────
            ui.horizontal(|ui| {
                if ui.button(RichText::new("Save").strong()).clicked() {
                    do_save = true;
                }
                if self.dirty.contains(&slug) {
                    ui.label(
                        RichText::new("● unsaved changes")
                            .color(Color32::from_rgb(0xd9, 0x95, 0x3f)),
                    );
                }
            });
            self.show_status(ui, &slug);
        });

        // Apply deferred actions now that the borrows above are released.
        if let Some(on) = set_all {
            self.config.set_all_capabilities(&slug, on);
            changed = true;
        }
        if do_reset {
            self.config.reset_endpoint(&slug);
            changed = true;
        }
        if let Some(idx) = clicked_idx {
            self.selected_cap = idx;
        }
        if changed {
            self.dirty.insert(slug.clone());
        }
        if do_save {
            self.save(&slug);
        }
        self.scroll_to_sel = false;
    }

    /// Read-only preview of the JSON persisted to disk for this ecosystem.
    fn config_json_tab(&mut self, ui: &mut egui::Ui) {
        let slug = self.selected.clone();
        let cfg = &self.config.ecosystems[&slug];
        let mut json = config::file_json(&slug, cfg);

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.heading("Config file");
            ui.label(
                RichText::new(config::ecosystem_path(&slug).display().to_string())
                    .monospace()
                    .weak(),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Copy").clicked() {
                    ui.ctx().copy_text(json.clone());
                }
            });
        });
        ui.add_space(6.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut json)
                    .code_editor()
                    .desired_width(f32::INFINITY)
                    .desired_rows(24)
                    .interactive(false),
            );
        });
    }

    /// Run the (stubbed) save for an ecosystem and record the outcome.
    fn save(&mut self, slug: &str) {
        let cfg = &self.config.ecosystems[slug];
        self.status = Some(match api::save(slug, cfg) {
            Ok(out) => {
                self.dirty.remove(slug);
                SaveStatus {
                    slug: slug.to_string(),
                    ok: true,
                    message: format!(
                        "Saved {} ({} bytes) — the engine reads this live.",
                        out.path.display(),
                        out.bytes
                    ),
                }
            }
            Err(e) => SaveStatus {
                slug: slug.to_string(),
                ok: false,
                message: format!("Save failed: {e}"),
            },
        });
    }

    /// Show the last save status, if it is for the current ecosystem.
    fn show_status(&self, ui: &mut egui::Ui, slug: &str) {
        if let Some(s) = &self.status {
            if s.slug == slug {
                let color = if s.ok {
                    Color32::from_rgb(0x4f, 0xa6, 0x7a)
                } else {
                    Color32::from_rgb(0xd9, 0x4f, 0x4f)
                };
                ui.add_space(4.0);
                ui.label(RichText::new(&s.message).color(color));
            }
        }
    }
}

/// A small coloured badge for a capability's finding class.
fn class_chip(ui: &mut egui::Ui, class: Class) {
    let color = class.color();
    egui::Frame::new()
        .fill(color.gamma_multiply(0.25))
        .stroke(egui::Stroke::new(1.0, color))
        .corner_radius(4.0)
        .inner_margin(egui::Margin::symmetric(6, 1))
        .show(ui, |ui| {
            ui.label(RichText::new(class.label()).color(color).size(11.0));
        });
}

/// One `key → action` pair in the bottom legend.
fn key_hint(ui: &mut egui::Ui, key: &str, action: &str) {
    ui.label(RichText::new(key).monospace().strong());
    ui.label(RichText::new(action).weak().size(12.0));
    ui.add_space(8.0);
}
