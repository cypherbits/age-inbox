use age_inbox::api::{router, AppState};
use std::{
    collections::HashMap,
    fs,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};
use tokio::sync::RwLock;

#[test]
fn router_builds_without_panicking() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let state = AppState {
        unlocked_vaults: Arc::new(RwLock::new(HashMap::new())),
        vaults_dir: tmp.path().to_path_buf(),
    };

    let result = catch_unwind(AssertUnwindSafe(|| router(state)));
    assert!(
        result.is_ok(),
        "router panicked while building; check Axum route syntax"
    );
}

#[test]
fn routes_do_not_use_legacy_axum_syntax() {
    let mod_rs_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("api")
        .join("mod.rs");

    let content = fs::read_to_string(&mod_rs_path).expect("read src/api/mod.rs");

    for (line_no, line) in content.lines().enumerate() {
        if !line.contains(".route(\"") {
            continue;
        }

        assert!(
            !line.contains("/:") && !line.contains("/*"),
            "legacy Axum route syntax found at {}:{} -> {}",
            mod_rs_path.display(),
            line_no + 1,
            line.trim()
        );
    }
}

