#![allow(dead_code)]

use std::path::PathBuf;
use tempfile::TempDir;

/// Helper struct to manage temporary test directories.
pub struct TestEnv {
    pub temp_dir: TempDir,
    pub vaults_dir: PathBuf,
}

impl TestEnv {
    /// Creates a new test environment with an isolated temporary directory.
    pub fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let vaults_dir = temp_dir.path().join("vaults");
        std::fs::create_dir_all(&vaults_dir).expect("Failed to create vaults dir");

        TestEnv {
            temp_dir,
            vaults_dir,
        }
    }

    /// Creates a test file with the specified content.
    pub fn create_test_file(&self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.temp_dir.path().join(name);
        std::fs::write(&path, content).expect("Failed to write test file");
        path
    }
}

