//! Coarse, masked, co-observed network-origin token ("observed prefix").
//!
//! When two peers hold a point-to-point QUIC connection, each side already
//! observes the other's remote address (the same observation that feeds the
//! bootstrap cache via `add_from_connection` and the NAT-traversal machinery).
//! This module coarsens that *already-observed* address into a masked CIDR
//! prefix so applications can reason about **origin diversity** (e.g.
//! anti-fraud "did these plays come from many independent networks?") without
//! ever seeing a raw IP.
//!
//! ## Privacy invariants
//!
//! - **Never a raw IP.** IPv4 is masked to `/24`, IPv6 to `/48`. The host
//!   portion is zeroed before the value is ever rendered to a string.
//! - **Point-to-point only.** The token is surfaced exclusively on surfaces
//!   fed by a direct connection to the peer (DM receive events, per-peer DM
//!   diagnostics). It is **never** gossiped, never stored in the DHT, and
//!   never attached to broadcast traffic — consistent with ADR-0006
//!   (point-to-point data stays with the participating peers).
//! - **Default OFF.** Per `docs/trust-and-connectivity.md`, x0x refuses to
//!   expose quasi-geolocation by default. The daemon only computes and
//!   surfaces this token when `observed_prefix_enabled = true` is set in the
//!   daemon TOML. When disabled, the fields are entirely absent from every
//!   serialized surface (not `null`) — wire behavior is byte-identical to a
//!   build without this module.
//! - **Nothing new is captured.** This is a coarsen-and-surface of an address
//!   the transport already knows; no additional observation is performed.
//!
//! ## Fields
//!
//! - `prefix` — the masked CIDR block, e.g. `"203.0.113.0/24"` or
//!   `"2001:db8::/48"`.
//! - `direct` — `true` when the masked address belongs to the peer itself
//!   (a direct point-to-point path). `false` when the only address available
//!   is an intermediary's (e.g. an application-level relay): the prefix is
//!   then the *relay's*, still masked, and consumers must not attribute it
//!   to the origin peer.
//! - `cgnat` — `true` when the observed address falls in the RFC 6598
//!   carrier-grade-NAT range (`100.64.0.0/10`). CGNAT prefixes are shared by
//!   many unrelated subscribers, so origin-diversity consumers should weight
//!   them accordingly.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};

/// A coarse, masked network-origin token for a point-to-point peer.
///
/// See the module docs for the privacy invariants. Construct via
/// [`ObservedPrefix::from_addr`] — the raw address never leaves this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedPrefix {
    /// Masked CIDR block: IPv4 `/24` (e.g. `"203.0.113.0/24"`) or IPv6 `/48`
    /// (e.g. `"2001:db8::/48"`).
    pub prefix: String,
    /// `true` if the masked address is the peer's own (direct path);
    /// `false` if it is an intermediary's (e.g. a relay), still masked.
    pub direct: bool,
    /// `true` if the observed address is in the RFC 6598 CGNAT range
    /// (`100.64.0.0/10`) — shared by many unrelated subscribers.
    pub cgnat: bool,
}

/// Mask an IPv4 address to its `/24` prefix, rendered as CIDR.
///
/// The last octet is zeroed: `203.0.113.7` → `"203.0.113.0/24"`.
#[must_use]
pub fn mask_v4(ip: Ipv4Addr) -> String {
    let masked = Ipv4Addr::from(u32::from(ip) & 0xFFFF_FF00);
    format!("{masked}/24")
}

/// Mask an IPv6 address to its `/48` prefix, rendered as CIDR.
///
/// Everything below the top 48 bits is zeroed:
/// `2001:db8:aaaa:bbbb::1` → `"2001:db8:aaaa::/48"`.
#[must_use]
pub fn mask_v6(ip: Ipv6Addr) -> String {
    let masked = Ipv6Addr::from(u128::from(ip) & (u128::MAX << 80));
    format!("{masked}/48")
}

impl ObservedPrefix {
    /// Coarsen an observed socket address into a masked origin token.
    ///
    /// `direct` is `true` when `addr` is the peer's own address on a
    /// point-to-point path, `false` when it is an intermediary's (relay).
    /// The port is discarded; the host bits are zeroed per [`mask_v4`] /
    /// [`mask_v6`]. Loopback, link-local, and private (RFC 1918) addresses
    /// are masked exactly like public ones — no raw IP ever escapes,
    /// including on test/LAN paths.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`, as reported by
    /// dual-stack sockets for v4 peers) are canonicalized to their IPv4 form
    /// first — otherwise every v4 peer observed through a dual-stack socket
    /// would collapse into the single `::/48` bucket, destroying the
    /// origin-diversity signal.
    #[must_use]
    pub fn from_addr(addr: SocketAddr, direct: bool) -> Self {
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 @ IpAddr::V4(_) => v4,
        };
        let prefix = match ip {
            IpAddr::V4(v4) => mask_v4(v4),
            IpAddr::V6(v6) => mask_v6(v6),
        };
        Self {
            prefix,
            direct,
            cgnat: crate::connectivity::is_cgnat(ip),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("valid socket addr")
    }

    #[test]
    fn masks_public_v4_to_slash_24() {
        let op = ObservedPrefix::from_addr(sa("203.0.113.77:5483"), true);
        assert_eq!(op.prefix, "203.0.113.0/24");
        assert!(op.direct);
        assert!(!op.cgnat);
    }

    #[test]
    fn masks_public_v6_to_slash_48() {
        let op = ObservedPrefix::from_addr(sa("[2001:db8:aaaa:bbbb::42]:5483"), true);
        assert_eq!(op.prefix, "2001:db8:aaaa::/48");
        assert!(op.direct);
        assert!(!op.cgnat);
    }

    #[test]
    fn detects_cgnat_range() {
        // RFC 6598 shared address space: 100.64.0.0/10.
        let op = ObservedPrefix::from_addr(sa("100.64.1.1:5483"), true);
        assert_eq!(op.prefix, "100.64.1.0/24");
        assert!(op.cgnat);

        // Upper edge of the /10.
        let op = ObservedPrefix::from_addr(sa("100.127.255.254:5483"), true);
        assert_eq!(op.prefix, "100.127.255.0/24");
        assert!(op.cgnat);

        // Just outside the /10 on both sides.
        assert!(!ObservedPrefix::from_addr(sa("100.63.255.255:1"), true).cgnat);
        assert!(!ObservedPrefix::from_addr(sa("100.128.0.1:1"), true).cgnat);
    }

    #[test]
    fn relay_path_masks_relay_addr_with_direct_false() {
        // When the only observable address is the relay's, the token carries
        // the relay's masked prefix and direct=false — never the origin's IP.
        let op = ObservedPrefix::from_addr(sa("198.51.100.9:443"), false);
        assert_eq!(op.prefix, "198.51.100.0/24");
        assert!(!op.direct);
        assert!(!op.cgnat);
    }

    #[test]
    fn loopback_and_private_ranges_still_masked_never_raw() {
        let lo = ObservedPrefix::from_addr(sa("127.0.0.1:12700"), true);
        assert_eq!(lo.prefix, "127.0.0.0/24");
        assert!(!lo.cgnat);

        let rfc1918 = ObservedPrefix::from_addr(sa("192.168.1.42:5483"), true);
        assert_eq!(rfc1918.prefix, "192.168.1.0/24");
        assert!(!rfc1918.cgnat);

        let lo6 = ObservedPrefix::from_addr(sa("[::1]:12700"), true);
        assert_eq!(lo6.prefix, "::/48");
        assert!(!lo6.cgnat);
    }

    #[test]
    fn ipv4_mapped_ipv6_is_canonicalized_to_v4_before_masking() {
        // Dual-stack sockets report v4 peers as ::ffff:a.b.c.d. Masking that
        // as v6 would bucket ALL such peers into "::/48" — the token must be
        // the peer's real v4 /24 instead.
        let op = ObservedPrefix::from_addr(sa("[::ffff:203.0.113.7]:5483"), true);
        assert_eq!(op.prefix, "203.0.113.0/24");
        assert!(!op.cgnat);

        // CGNAT detection also sees through the mapping.
        let op = ObservedPrefix::from_addr(sa("[::ffff:100.64.1.1]:5483"), true);
        assert_eq!(op.prefix, "100.64.1.0/24");
        assert!(op.cgnat);

        // Mapped loopback stays masked-v4.
        let op = ObservedPrefix::from_addr(sa("[::ffff:127.0.0.1]:5483"), true);
        assert_eq!(op.prefix, "127.0.0.0/24");
    }

    #[test]
    fn mask_v4_zeroes_host_octet_at_boundaries() {
        assert_eq!(mask_v4(Ipv4Addr::new(10, 0, 0, 0)), "10.0.0.0/24");
        assert_eq!(mask_v4(Ipv4Addr::new(10, 0, 0, 255)), "10.0.0.0/24");
        assert_eq!(
            mask_v4(Ipv4Addr::new(255, 255, 255, 255)),
            "255.255.255.0/24"
        );
    }

    #[test]
    fn mask_v6_zeroes_below_48_bits() {
        let ip: Ipv6Addr = "2001:db8:1:ffff:ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(mask_v6(ip), "2001:db8:1::/48");
    }

    #[test]
    fn serializes_to_expected_json_shape() {
        let op = ObservedPrefix::from_addr(sa("203.0.113.77:5483"), true);
        let json = serde_json::to_value(&op).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({
                "prefix": "203.0.113.0/24",
                "direct": true,
                "cgnat": false,
            })
        );
    }

    #[test]
    fn never_contains_host_bits_in_rendered_prefix() {
        // Property-ish sweep: for a spread of host octets the rendered string
        // must not contain the unmasked address.
        for host in [1u8, 7, 42, 128, 200, 254] {
            let addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, host), 5483));
            let op = ObservedPrefix::from_addr(addr, true);
            assert_eq!(op.prefix, "203.0.113.0/24");
            assert!(!op.prefix.contains(&format!("113.{host}")) || host == 0);
        }
    }
}
