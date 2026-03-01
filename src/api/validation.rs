/// Validates a vault name used in path segments and filesystem paths.
pub(crate) fn is_valid_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && !name.contains('\\') && !name.contains("..")
}

/// Validates a subpath to avoid path traversal and absolute paths.
pub(crate) fn is_valid_subpath(path: &str) -> bool {
    !path.contains("..") && !path.starts_with('/') && !path.contains('\\')
}