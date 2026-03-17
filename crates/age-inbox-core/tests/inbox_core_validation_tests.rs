mod common;

use age_inbox_core::inbox_core::{is_valid_name, is_valid_subpath, metadata_sidecar_for};
use std::path::Path;

// ============================================================================
// is_valid_name tests
// ============================================================================

/// Test: Empty name is invalid.
#[test]
fn test_is_valid_name_empty() {
    assert!(!is_valid_name(""), "Empty name should be invalid");
}

/// Test: Valid alphanumeric name.
#[test]
fn test_is_valid_name_alphanumeric() {
    assert!(is_valid_name("testvault"), "Alphanumeric name should be valid");
    assert!(is_valid_name("vault123"), "Name with numbers should be valid");
}

/// Test: Names with forward slash are invalid.
#[test]
fn test_is_valid_name_with_forward_slash() {
    assert!(!is_valid_name("vault/name"), "Name with forward slash should be invalid");
}

/// Test: Names with backslash are invalid.
#[test]
fn test_is_valid_name_with_backslash() {
    assert!(!is_valid_name("vault\\name"), "Name with backslash should be invalid");
}

/// Test: Names with parent directory reference are invalid.
#[test]
fn test_is_valid_name_with_parent_dir_reference() {
    assert!(!is_valid_name(".."), "Parent directory reference should be invalid");
    assert!(!is_valid_name("vault..name"), "Name containing '..' should be invalid");
    assert!(!is_valid_name("../vault"), "Name starting with '..' should be invalid");
}

/// Test: Names with hyphens and underscores are valid.
#[test]
fn test_is_valid_name_with_special_valid_chars() {
    assert!(is_valid_name("my-vault"), "Name with hyphen should be valid");
    assert!(is_valid_name("my_vault"), "Name with underscore should be valid");
    assert!(is_valid_name("my-vault_123"), "Name with hyphens and underscores should be valid");
}

/// Test: Names with spaces are valid (but unusual).
#[test]
fn test_is_valid_name_with_spaces() {
    assert!(is_valid_name("my vault"), "Name with spaces should be technically valid");
}

// ============================================================================
// is_valid_subpath tests
// ============================================================================

/// Test: Empty subpath is valid (represents root).
#[test]
fn test_is_valid_subpath_empty() {
    assert!(is_valid_subpath(""), "Empty subpath should be valid");
}

/// Test: Simple filename.
#[test]
fn test_is_valid_subpath_simple_filename() {
    assert!(is_valid_subpath("file.txt"), "Simple filename should be valid");
    assert!(is_valid_subpath("data.age"), "Encrypted filename should be valid");
}

/// Test: Nested path with forward slashes.
#[test]
fn test_is_valid_subpath_nested() {
    assert!(is_valid_subpath("folder/subfolder/file.txt"), "Nested path should be valid");
}

/// Test: Paths starting with forward slash are invalid.
#[test]
fn test_is_valid_subpath_absolute_path() {
    assert!(!is_valid_subpath("/file.txt"), "Absolute path should be invalid");
    assert!(!is_valid_subpath("/folder/file"), "Absolute path should be invalid");
}

/// Test: Paths with backslashes are invalid.
#[test]
fn test_is_valid_subpath_with_backslash() {
    assert!(!is_valid_subpath("folder\\file.txt"), "Backslash in path should be invalid");
}

/// Test: Parent directory references are invalid.
#[test]
fn test_is_valid_subpath_with_parent_dir_reference() {
    assert!(!is_valid_subpath(".."), "Parent directory reference should be invalid");
    assert!(!is_valid_subpath("../file"), "Parent directory reference in path should be invalid");
    assert!(!is_valid_subpath("folder/../file"), "Parent directory traversal should be invalid");
    assert!(!is_valid_subpath("file..txt"), "Contains '..' should be invalid");
}

/// Test: Single dot path is valid (current directory).
#[test]
fn test_is_valid_subpath_single_dot() {
    assert!(is_valid_subpath("."), "Single dot (current directory) should be valid");
    assert!(is_valid_subpath("./file.txt"), "Relative path with ./ should be valid");
}

/// Test: Complex nested paths.
#[test]
fn test_is_valid_subpath_complex_nested() {
    assert!(is_valid_subpath("a/b/c/d/e/f.txt"), "Deep nested path should be valid");
    assert!(is_valid_subpath("folder-1/subfolder_2/file-3.age"), "Complex nested path should be valid");
}

// ============================================================================
// metadata_sidecar_for tests
// ============================================================================

/// Test: Normal .age file generates correct sidecar name.
#[test]
fn test_metadata_sidecar_for_normal_age_file() {
    let path = Path::new("folder/file.age");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_some(), "Normal .age file should have a sidecar");
    let sidecar_str = sidecar.unwrap().to_string_lossy().to_string();
    assert!(sidecar_str.ends_with("file.meta.age"), "Sidecar should have .meta.age extension");
}

/// Test: .meta.age files don't generate sidecars (already metadata).
#[test]
fn test_metadata_sidecar_for_meta_age_file() {
    let path = Path::new("file.meta.age");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_none(), ".meta.age file should not have a sidecar");
}

/// Test: Non-.age files don't generate sidecars.
#[test]
fn test_metadata_sidecar_for_non_age_file() {
    let path = Path::new("file.txt");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_none(), "Non-.age file should not have a sidecar");
}

/// Test: Files without extension.
#[test]
fn test_metadata_sidecar_for_no_extension() {
    let path = Path::new("file");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_none(), "File without extension should not have a sidecar");
}

/// Test: Sidecar preserves folder structure.
#[test]
fn test_metadata_sidecar_for_preserves_path() {
    let path = Path::new("folder1/folder2/file.age");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_some(), "Nested file should have a sidecar");
    let sidecar_str = sidecar.unwrap().to_string_lossy().to_string();
    assert!(sidecar_str.ends_with("file.meta.age"), "Sidecar should end with .meta.age");
    assert!(sidecar_str.contains("folder1") && sidecar_str.contains("folder2"), "Sidecar should preserve folder structure");
}

/// Test: Multiple .age extensions (unusual case).
#[test]
fn test_metadata_sidecar_for_multiple_age_extensions() {
    let path = Path::new("file.data.age");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_some(), "File with .data.age should have sidecar");
    assert_eq!(
        sidecar.unwrap().to_string_lossy(),
        "file.data.meta.age",
        "Sidecar should replace only last .age"
    );
}

/// Test: Deeply nested .age file.
#[test]
fn test_metadata_sidecar_for_deeply_nested() {
    let path = Path::new("a/b/c/d/e/f/file.age");
    let sidecar = metadata_sidecar_for(path);

    assert!(sidecar.is_some(), "Deeply nested file should have sidecar");
    let sidecar_str = sidecar.unwrap().to_string_lossy().to_string();
    assert!(sidecar_str.ends_with("file.meta.age"), "Sidecar should end with .meta.age");
    assert!(sidecar_str.starts_with("a/b/c"), "Sidecar should preserve path prefix");
}

