//! Native configuration frontend for the Vulnetix `malscan-engine`.
//!
//! The engine itself (the sibling Go module) is ecosystem-agnostic: every
//! registry processor maps its package into a `PackageContext` and the same
//! detector set runs over it. Not every detector is meaningful for every
//! registry, though — `-bin` source verification is an AUR convention, registry
//! comment scanning only exists where a registry has user comments, and so on.
//!
//! This app surfaces that: pick an ecosystem, and the Overview tab lists exactly
//! the engine capabilities that ecosystem supports, each with an on/off toggle,
//! plus the ecosystem's registry endpoint. Saving is stubbed (see `api.rs`) so a
//! real backend can be wired in later without touching the UI.

mod api;
mod app;
mod config;
mod model;

fn main() -> eframe::Result {
    // `--write-defaults` regenerates the committed repo defaults and exits — the
    // maintenance path for refreshing config/defaults/*.json after a catalog edit.
    if std::env::args().skip(1).any(|a| a == "--write-defaults") {
        let dir = config::defaults_dir();
        match config::write_all_defaults(&dir) {
            Ok(paths) => {
                for p in paths {
                    println!("wrote {}", p.display());
                }
            }
            Err(e) => {
                eprintln!("write-defaults: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([960.0, 700.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("malscan-engine — frontend"),
        ..Default::default()
    };

    eframe::run_native(
        "malscan-engine frontend",
        options,
        Box::new(|cc| Ok(Box::new(app::MalscanApp::new(cc)))),
    )
}
