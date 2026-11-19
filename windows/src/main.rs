// SPDX-FileCopyrightText: 2026 FastKiwi (Sarmad)
// SPDX-License-Identifier: Apache-2.0
//! Kiwi Transfer for Windows. No UI yet: the WebView2 window arrives later.

/// The program version, from Cargo.toml.
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn main() {
    println!("Kiwi Transfer {}", version());
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_semver_shaped() {
        assert_eq!(super::version().split('.').count(), 3);
    }
}
