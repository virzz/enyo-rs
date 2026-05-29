use std::{env, fs, path::Path};

fn workspace_members(manifest: &str) -> &str {
    manifest
        .split_once("members = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(members, _)| members)
        .expect("workspace members")
}

#[test]
fn root_manifest_declares_enyo_package_with_crates_enyo_sources() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read root Cargo.toml");

    assert!(manifest.contains("[package]"));
    assert!(manifest.contains("name = \"enyo\""));
    assert!(manifest.contains("build = \"crates/enyo/build.rs\""));
    assert!(manifest.contains("path = \"crates/enyo/src/lib.rs\""));
    assert!(manifest.contains("path = \"crates/enyo/src/main.rs\""));

    assert!(manifest.contains("[workspace]"));
    assert!(manifest.contains("\"crates/core\""));
    assert!(manifest.contains("\"crates/*\""));
    assert!(!workspace_members(&manifest).contains("\"crates/enyo\""));
    assert!(manifest.contains("exclude = [\"crates/enyo\"]"));

    assert!(workspace_root.join("crates/enyo/src/lib.rs").exists());
    assert!(workspace_root.join("crates/enyo/src/main.rs").exists());
    assert!(!workspace_root.join("crates/enyo/Cargo.toml").exists());
}

#[test]
fn each_command_directory_has_a_workspace_manifest() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));

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
