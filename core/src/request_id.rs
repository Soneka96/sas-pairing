//! Crate-private honest Initiator request-ID generation (P3 §4): exactly 16 raw bytes from
//! the OS-backed CSPRNG. The ID is public, non-secret routing/correlation data only; it is not
//! ceremony identity, authentication, authorization, freshness, or trust, and protocol
//! authentication never depends on its unpredictability. Uniqueness among live local
//! Initiators comes from the authority's atomic reservation, not from this generator.
#![allow(dead_code)] // Used only by the internal ceremony until later P4 work defines its API.

/// Source of candidate request IDs. Application code never supplies one: production uses
/// `OsRequestIds`, and only tests inject scripted candidates.
pub(crate) trait RequestIdGenerator {
    /// One fresh candidate, or `None` when the source cannot produce one. Callers fail closed.
    fn generate(&mut self) -> Option<[u8; 16]>;
}

/// Production source: `getrandom::fill`, the operating system's CSPRNG (Windows `ProcessPrng`).
pub(crate) struct OsRequestIds;

impl RequestIdGenerator for OsRequestIds {
    fn generate(&mut self) -> Option<[u8; 16]> {
        let mut id = [0; 16];
        // OS error details are deliberately not retained or exposed.
        getrandom::fill(&mut id).ok()?;
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_source_yields_exactly_sixteen_raw_bytes() {
        // Structural only: random values are never asserted to differ.
        let id: [u8; 16] = OsRequestIds.generate().unwrap();
        assert_eq!(id.len(), 16);
    }
}
