/// Parses a single `Range: bytes=start-end` value against a known resource size.
/// Returns inclusive `(start, end)` on success.
pub(crate) fn parse_single_range(header_value: &str, file_size: u64) -> Option<(u64, u64)> {
    if !header_value.starts_with("bytes=") || header_value.contains(',') {
        return None;
    }

    let spec = &header_value[6..];
    let (start_str, end_str) = spec.split_once('-')?;

    // Empty resource cannot satisfy any byte range.
    if file_size == 0 {
        return None;
    }

    if start_str.is_empty() {
        // suffix range: bytes=-500 means last 500 bytes
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 || suffix_len > file_size {
            return None;
        }
        let start = file_size.checked_sub(suffix_len)?;
        return Some((start, file_size - 1));
    }

    let start: u64 = start_str.parse().ok()?;
    if start >= file_size {
        return None;
    }

    let end = if end_str.is_empty() {
        file_size - 1
    } else {
        let parsed_end: u64 = end_str.parse().ok()?;
        parsed_end.min(file_size - 1)
    };

    if start > end {
        return None;
    }

    Some((start, end))
}

pub(crate) fn unsatisfied_content_range(file_size: u64) -> String {
    format!("bytes */{}", file_size)
}
