use std::{env, fs, path::Path};

#[test]
fn root_manifest_declares_workspace_members_for_app_core_and_each_command_crate() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read root Cargo.toml");

    assert!(manifest.contains("[workspace]"));
    assert!(manifest.contains("\"crates/enyo\""));
    assert!(manifest.contains("\"crates/core\""));
    assert!(manifest.contains("\"crates/*\""));

    assert!(workspace_root.join("crates/enyo/Cargo.toml").exists());
    assert!(workspace_root.join("crates/core/Cargo.toml").exists());

    let entries = fs::read_dir(workspace_root.join("crates")).expect("read crates");
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join("src/mod.rs").exists() {
            continue;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == "core" {
            continue;
        }

        assert!(
            workspace_root
                .join("crates")
                .join(name.as_ref())
                .join("Cargo.toml")
                .exists(),
            "missing command crate manifest for crates/{name}"
        );
    }
}
