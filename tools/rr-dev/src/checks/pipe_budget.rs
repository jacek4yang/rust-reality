//! Pipe-page budget model from `benchmark-matrix.sh`.
//!
//! The matrix harness sizes `fs.pipe-user-pages-soft` from a closed formula over
//! page size and peak concurrency. The release performance-gates Python used to
//! extract those assignments from the shell script and assert the numbers; this
//! module owns the formula natively so the shell is no longer the source of
//! truth.

#![allow(dead_code)]

/// Peak pipe-page budget for a given page size and max concurrency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeBudget {
    /// Pages per rust-reality pipe.
    pub rust_pages_per_pipe: u64,
    /// Pages per Xray pipe.
    pub xray_pages_per_pipe: u64,
    /// Tunnel peak pages.
    pub tunnel_peak: u64,
    /// Fallback peak pages.
    pub fallback_peak: u64,
    /// Combined peak pages.
    pub peak: u64,
    /// Required soft limit (2× peak).
    pub required: u64,
}

/// Computes the matrix pipe-page budget.
///
/// Matches `benchmark-matrix.sh`:
/// ```text
/// rust_pages_per_pipe  = ceil(256 KiB / page)
/// xray_pages_per_pipe  = ceil(1 MiB / page)
/// tunnel_peak          = (2*rust + 4*xray) * 2 * (2*max_concurrency)
/// fallback_peak        = (2*rust + xray) * 2 * max_concurrency
/// peak                 = tunnel + fallback
/// required             = 2 * peak
/// ```
#[must_use]
pub fn compute(page_size: u64, max_concurrency: u64) -> PipeBudget {
    let rust_pages_per_pipe = 256_u64.saturating_mul(1024).div_ceil(page_size);
    let xray_pages_per_pipe = 1024_u64.saturating_mul(1024).div_ceil(page_size);
    let tunnel_peak =
        (2 * rust_pages_per_pipe + 4 * xray_pages_per_pipe) * 2 * (2 * max_concurrency);
    let fallback_peak = (2 * rust_pages_per_pipe + xray_pages_per_pipe) * 2 * max_concurrency;
    let peak = tunnel_peak + fallback_peak;
    PipeBudget {
        rust_pages_per_pipe,
        xray_pages_per_pipe,
        tunnel_peak,
        fallback_peak,
        peak,
        required: peak * 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_legacy_4096_page_32_concurrency_budget_is_reproduced() {
        let budget = compute(4096, 32);
        assert_eq!(budget.tunnel_peak, 147_456);
        assert_eq!(budget.fallback_peak, 24_576);
        assert_eq!(budget.peak, 172_032);
        assert_eq!(budget.required, 344_064);
        assert_eq!(budget.rust_pages_per_pipe, 64);
        assert_eq!(budget.xray_pages_per_pipe, 256);
    }
}
