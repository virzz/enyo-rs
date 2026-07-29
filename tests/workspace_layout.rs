use std::{env, fs, path::Path};

#[test]
fn root_manifest_declares_enyo_package_with_root_sources() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read root Cargo.toml");

    assert!(manifest.contains("[package]"));
    assert!(manifest.contains("name = \"enyo\""));
    assert!(manifest.contains("build = \"build.rs\""));
    assert!(manifest.contains("path = \"src/lib.rs\""));
    assert!(manifest.contains("path = \"src/main.rs\""));

    assert!(manifest.contains("[workspace]"));
    assert!(manifest.contains("\"crates/core\""));
    assert!(manifest.contains("\"crates/*\""));
    assert!(manifest.contains("default-members = [\".\"]"));
    assert!(!manifest.contains("crates/enyo"));

    assert!(workspace_root.join("build.rs").exists());
    assert!(workspace_root.join("src/lib.rs").exists());
    assert!(workspace_root.join("src/main.rs").exists());
    assert!(!workspace_root.join("crates/enyo").exists());
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

#[test]
fn external_commands_are_metadata_driven() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest =
        fs::read_to_string(workspace_root.join("Cargo.toml")).expect("read root Cargo.toml");
    let build_script = fs::read_to_string(workspace_root.join("build.rs"))
        .expect("read command registry generator");
    let command_registry = fs::read_to_string(workspace_root.join("src/cmds.rs"))
        .expect("read generated command registry");

    assert!(manifest.contains("[package.metadata.enyo.external-commands.llmapi]"));
    assert!(manifest.contains("llmapi = { path = \"../llmapi-rs\" }"));
    assert!(!workspace_root.join("crates/llmapi").exists());
    assert!(workspace_root.join("../llmapi-rs/Cargo.toml").exists());
    assert!(build_script.contains("external-commands"));
    assert!(!build_script.contains("llmapi"));
    assert!(command_registry.contains("Llmapi(llmapi::Cmd)"));
}
