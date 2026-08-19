//! The `version` command — prints the version.

pub fn run() {
    println!("Skill Doctor v{}", env!("CARGO_PKG_VERSION"));
}
