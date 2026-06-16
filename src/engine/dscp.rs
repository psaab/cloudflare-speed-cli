//! DSCP (Differentiated Services Code Point) socket marking.
//!
//! Sets the DSCP field — the upper 6 bits of the IPv4 TOS byte (`IP_TOS`) or the
//! IPv6 Traffic Class byte (`IPV6_TCLASS`) — on sockets so test traffic can be
//! classified by QoS-aware network equipment. The lower 2 ECN bits are left
//! zero.
//!
//! This covers every socket the test opens: the sockets created directly here
//! (the TLS handshake probe, the UDP/STUN packet-loss probe, and the raw-ICMP
//! traceroute) plus the HTTP download/upload throughput and HTTP diagnostics,
//! which run through a vendored `reqwest`/`hyper-util` fork (see `vendor/`) that
//! adds a `ClientBuilder::tos()` to thread the TOS byte down to the connector.

use anyhow::{anyhow, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Parse a DSCP specifier into its 6-bit value (0-63).
///
/// Accepts well-known keywords (case-insensitive) or a number. Keywords:
/// `be`/`cs0`/`default`, `le`, `cs1`..`cs7`, `af11`..`af43`, `ef`,
/// `va`/`voice-admit`. Numbers may be decimal or hex (`0x`-prefixed) and must be
/// in the range 0-63.
pub fn parse_dscp(s: &str) -> Result<u8> {
    let t = s.trim().to_ascii_lowercase();

    let by_name = match t.as_str() {
        "be" | "cs0" | "default" => Some(0u8),
        "le" => Some(1),
        "cs1" => Some(8),
        "cs2" => Some(16),
        "cs3" => Some(24),
        "cs4" => Some(32),
        "cs5" => Some(40),
        "cs6" => Some(48),
        "cs7" => Some(56),
        "af11" => Some(10),
        "af12" => Some(12),
        "af13" => Some(14),
        "af21" => Some(18),
        "af22" => Some(20),
        "af23" => Some(22),
        "af31" => Some(26),
        "af32" => Some(28),
        "af33" => Some(30),
        "af41" => Some(34),
        "af42" => Some(36),
        "af43" => Some(38),
        "ef" => Some(46),
        "va" | "voice-admit" => Some(44),
        _ => None,
    };
    if let Some(v) = by_name {
        return Ok(v);
    }

    let num = if let Some(hex) = t.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        t.parse::<u16>()
    }
    .map_err(|_| {
        anyhow!(
            "invalid DSCP value '{}': expected a keyword (e.g. ef, cs5, af41) or a number 0-63",
            s
        )
    })?;

    if num > 63 {
        return Err(anyhow!("DSCP value {} out of range (must be 0-63)", num));
    }
    Ok(num as u8)
}

/// The IP TOS / IPv6 Traffic Class byte for a DSCP value: DSCP in the high 6
/// bits, ECN cleared.
pub fn tos_byte(dscp: u8) -> u32 {
    ((dscp & 0x3f) as u32) << 2
}

/// The standard DiffServ class name for a DSCP value (`EF`, `CS5`, `AF41`,
/// `LE`, `VA`, `CS0`, ...), or `None` for a value with no well-known name. The
/// name is identical for IPv4 (`IP_TOS`/DS field) and IPv6 (Traffic Class).
pub fn dscp_name(dscp: u8) -> Option<&'static str> {
    Some(match dscp & 0x3f {
        0 => "CS0", // a.k.a. Default / Best-Effort
        8 => "CS1",
        16 => "CS2",
        24 => "CS3",
        32 => "CS4",
        40 => "CS5",
        48 => "CS6",
        56 => "CS7",
        10 => "AF11",
        12 => "AF12",
        14 => "AF13",
        18 => "AF21",
        20 => "AF22",
        22 => "AF23",
        26 => "AF31",
        28 => "AF32",
        30 => "AF33",
        34 => "AF41",
        36 => "AF42",
        38 => "AF43",
        44 => "VA", // Voice-Admit
        46 => "EF",
        1 => "LE", // Lower-Effort
        _ => return None,
    })
}

/// Format a single DSCP value as `NAME (DSCP <dec>, 0x<tos>)`, e.g.
/// `EF (DSCP 46, 0xB8)`. The `0x<tos>` byte is what gets written to IPv4
/// `IP_TOS` and IPv6 `IPV6_TCLASS` (identical for both). Values with no standard
/// class name render as `DSCP <dec> (0x<tos>)`.
pub fn describe_dscp(dscp: u8) -> String {
    let tos = tos_byte(dscp);
    match dscp_name(dscp) {
        Some(name) => format!("{} (DSCP {}, 0x{:02X})", name, dscp, tos),
        None => format!("DSCP {} (0x{:02X})", dscp, tos),
    }
}

/// A single DSCP value and its relative selection weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DscpWeight {
    pub dscp: u8,
    pub weight: u32,
}

/// Parse a `--dscp` specifier into a list of weighted DSCP values.
///
/// Format: `tos:weight,tos:weight,...` where each `tos` is a keyword (e.g. `ef`,
/// `cs5`, `af41`) or a number 0-63. Rules:
/// - If **every** entry has an explicit weight, the weights must sum to 100
///   (they are read as percentages).
/// - If **no** entry has a weight, all entries are weighted equally (this also
///   covers the single-DSCP case, e.g. `--dscp ef` → 100% `ef`).
/// - Mixing weighted and unweighted entries is rejected.
pub fn parse_dscp_weights(spec: &str) -> Result<Vec<DscpWeight>> {
    let tokens: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.is_empty() {
        return Err(anyhow!("empty --dscp value"));
    }

    // Parse each token into (dscp, optional explicit weight).
    let mut parsed: Vec<(u8, Option<u32>)> = Vec::with_capacity(tokens.len());
    for token in &tokens {
        // DSCP keywords/numbers never contain ':', so a colon always separates
        // the weight.
        let (val, weight) = match token.split_once(':') {
            Some((v, w)) => {
                let w = w.trim();
                let weight: u32 = w.parse().map_err(|_| {
                    anyhow!(
                        "invalid DSCP weight '{}' in '{}': expected a non-negative integer",
                        w,
                        token
                    )
                })?;
                (v.trim(), Some(weight))
            }
            None => (token.trim(), None),
        };
        let dscp = parse_dscp(val)?;
        parsed.push((dscp, weight));
    }

    let any_weighted = parsed.iter().any(|(_, w)| w.is_some());
    let all_weighted = parsed.iter().all(|(_, w)| w.is_some());

    if any_weighted && !all_weighted {
        return Err(anyhow!(
            "give a weight for every DSCP (e.g. ef:60,cs1:40) or for none (equal split)"
        ));
    }

    if all_weighted {
        let total: u32 = parsed.iter().map(|(_, w)| w.unwrap()).sum();
        if total != 100 {
            return Err(anyhow!(
                "--dscp weights must sum to 100, got {}",
                total
            ));
        }
        Ok(parsed
            .into_iter()
            .map(|(dscp, w)| DscpWeight {
                dscp,
                weight: w.unwrap(),
            })
            .collect())
    } else {
        // No weights given: equal split across all entries.
        Ok(parsed
            .into_iter()
            .map(|(dscp, _)| DscpWeight { dscp, weight: 1 })
            .collect())
    }
}

/// A ready-to-use weighted distribution of DSCP values. Built from a non-empty
/// list of [`DscpWeight`]s with at least one positive weight.
#[derive(Debug, Clone)]
pub struct DscpDist {
    /// (dscp, weight) pairs with weight > 0.
    entries: Vec<(u8, u32)>,
    total: u64,
}

impl DscpDist {
    /// Build a distribution, dropping zero-weight entries. Returns `None` if no
    /// usable entries remain (empty input or all weights zero).
    pub fn from_weights(weights: &[DscpWeight]) -> Option<Self> {
        let entries: Vec<(u8, u32)> = weights
            .iter()
            .filter(|w| w.weight > 0)
            .map(|w| (w.dscp, w.weight))
            .collect();
        let total: u64 = entries.iter().map(|(_, w)| *w as u64).sum();
        if entries.is_empty() || total == 0 {
            return None;
        }
        Some(Self { entries, total })
    }

    /// Weighted-random pick of one DSCP value.
    pub fn select(&self) -> u8 {
        if self.entries.len() == 1 {
            return self.entries[0].0;
        }
        let mut r = rand::thread_rng().gen_range(0..self.total);
        for (dscp, weight) in &self.entries {
            let w = *weight as u64;
            if r < w {
                return *dscp;
            }
            r -= w;
        }
        // Unreachable: r < total and the weights sum to total.
        self.entries.last().unwrap().0
    }

    /// A per-connection picker for the vendored reqwest/hyper-util fork: returns
    /// a weighted-random TOS byte for each new connection.
    pub fn picker(&self) -> Arc<dyn Fn() -> Option<u32> + Send + Sync> {
        let dist = self.clone();
        Arc::new(move || Some(tos_byte(dist.select())))
    }

    /// Human-readable summary including class name, decimal DSCP, the TOS /
    /// Traffic-Class byte, and the weight, e.g.
    /// `EF (DSCP 46, 0xB8) 60%, CS1 (DSCP 8, 0x20) 40%`.
    pub fn describe(&self) -> String {
        self.entries
            .iter()
            .map(|(dscp, weight)| {
                let pct = (*weight as f64) / (self.total as f64) * 100.0;
                format!("{} {:.0}%", describe_dscp(*dscp), pct)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Set the DSCP marking on a socket given its raw file descriptor.
///
/// `is_ipv6` selects between `IPV6_TCLASS` and `IP_TOS`. Best-effort: callers
/// should treat an error as "marking unavailable" and continue, not abort.
#[cfg(unix)]
pub fn apply<S: std::os::unix::io::AsRawFd>(sock: &S, dscp: u8, is_ipv6: bool) -> Result<()> {
    let tos = tos_byte(dscp) as libc::c_int;
    let (level, optname, name) = if is_ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_TCLASS, "IPV6_TCLASS")
    } else {
        (libc::IPPROTO_IP, libc::IP_TOS, "IP_TOS")
    };

    // SAFETY: `tos` is a valid `c_int` we own; its size matches the passed
    // socklen; the fd is owned by `sock` for the duration of the call.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            optname,
            &tos as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(anyhow!(
            "failed to set DSCP via {}: {}",
            name,
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn apply<S>(_sock: &S, _dscp: u8, _is_ipv6: bool) -> Result<()> {
    Err(anyhow!("DSCP marking is not supported on this platform"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_keywords_case_insensitively() {
        assert_eq!(parse_dscp("ef").unwrap(), 46);
        assert_eq!(parse_dscp("EF").unwrap(), 46);
        assert_eq!(parse_dscp("cs5").unwrap(), 40);
        assert_eq!(parse_dscp("AF41").unwrap(), 34);
        assert_eq!(parse_dscp("be").unwrap(), 0);
        assert_eq!(parse_dscp("cs0").unwrap(), 0);
        assert_eq!(parse_dscp("default").unwrap(), 0);
        assert_eq!(parse_dscp("le").unwrap(), 1);
        assert_eq!(parse_dscp("va").unwrap(), 44);
        assert_eq!(parse_dscp("voice-admit").unwrap(), 44);
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_dscp("  ef  ").unwrap(), 46);
        assert_eq!(parse_dscp(" 46 ").unwrap(), 46);
    }

    #[test]
    fn parses_decimal_and_hex_numbers() {
        assert_eq!(parse_dscp("0").unwrap(), 0);
        assert_eq!(parse_dscp("46").unwrap(), 46);
        assert_eq!(parse_dscp("63").unwrap(), 63);
        assert_eq!(parse_dscp("0x2e").unwrap(), 46);
        assert_eq!(parse_dscp("0x3F").unwrap(), 63);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(parse_dscp("64").is_err());
        assert!(parse_dscp("255").is_err());
        assert!(parse_dscp("0x40").is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_dscp("nonsense").is_err());
        assert!(parse_dscp("").is_err());
        assert!(parse_dscp("cs8").is_err());
    }

    #[test]
    fn tos_byte_shifts_left_two_and_clears_ecn() {
        assert_eq!(tos_byte(46), 0xB8); // EF -> 184 -> 0xB8
        assert_eq!(tos_byte(0), 0);
        assert_eq!(tos_byte(63), 0xFC);
        // High bits beyond 6 are masked off.
        assert_eq!(tos_byte(0xFF), 0xFC);
    }

    fn pairs(ws: &[DscpWeight]) -> Vec<(u8, u32)> {
        ws.iter().map(|w| (w.dscp, w.weight)).collect()
    }

    #[test]
    fn weights_single_value_defaults_to_full_share() {
        // A lone DSCP with no weight is the equal-split case with one entry.
        assert_eq!(pairs(&parse_dscp_weights("ef").unwrap()), vec![(46, 1)]);
        assert_eq!(pairs(&parse_dscp_weights("0x2e").unwrap()), vec![(46, 1)]);
    }

    #[test]
    fn weights_omitted_means_equal_split() {
        assert_eq!(
            pairs(&parse_dscp_weights("ef,cs1,af21").unwrap()),
            vec![(46, 1), (8, 1), (18, 1)]
        );
        // Whitespace around tokens is tolerated.
        assert_eq!(
            pairs(&parse_dscp_weights(" ef , cs1 ").unwrap()),
            vec![(46, 1), (8, 1)]
        );
    }

    #[test]
    fn weights_explicit_must_sum_to_100() {
        assert_eq!(
            pairs(&parse_dscp_weights("ef:60,cs1:40").unwrap()),
            vec![(46, 60), (8, 40)]
        );
        assert_eq!(pairs(&parse_dscp_weights("ef:100").unwrap()), vec![(46, 100)]);
        assert_eq!(
            pairs(&parse_dscp_weights("ef:50,cs1:30,af21:20").unwrap()),
            vec![(46, 50), (8, 30), (18, 20)]
        );
    }

    #[test]
    fn weights_wrong_sum_rejected() {
        let err = parse_dscp_weights("ef:60,cs1:30").unwrap_err().to_string();
        assert!(err.contains("sum to 100"), "got: {err}");
        assert!(parse_dscp_weights("ef:50").is_err());
    }

    #[test]
    fn weights_mixed_specified_and_unspecified_rejected() {
        assert!(parse_dscp_weights("ef:60,cs1").is_err());
        assert!(parse_dscp_weights("ef,cs1:100").is_err());
    }

    #[test]
    fn weights_empty_and_garbage_rejected() {
        assert!(parse_dscp_weights("").is_err());
        assert!(parse_dscp_weights(",,").is_err());
        assert!(parse_dscp_weights("ef:abc").is_err());
        assert!(parse_dscp_weights("bogus:50,ef:50").is_err());
    }

    #[test]
    fn dist_single_entry_always_selects_it() {
        let dist = DscpDist::from_weights(&parse_dscp_weights("ef").unwrap()).unwrap();
        for _ in 0..100 {
            assert_eq!(dist.select(), 46);
        }
    }

    #[test]
    fn dist_select_only_returns_members() {
        let dist =
            DscpDist::from_weights(&parse_dscp_weights("ef:50,cs1:30,af21:20").unwrap()).unwrap();
        let members = [46u8, 8, 18];
        for _ in 0..500 {
            assert!(members.contains(&dist.select()));
        }
    }

    #[test]
    fn dist_drops_zero_weight_and_none_when_empty() {
        // All-zero weights -> no usable distribution.
        let zero = vec![DscpWeight { dscp: 46, weight: 0 }];
        assert!(DscpDist::from_weights(&zero).is_none());
        assert!(DscpDist::from_weights(&[]).is_none());
    }

    #[test]
    fn dscp_name_maps_known_classes() {
        assert_eq!(dscp_name(46), Some("EF"));
        assert_eq!(dscp_name(40), Some("CS5"));
        assert_eq!(dscp_name(34), Some("AF41"));
        assert_eq!(dscp_name(30), Some("AF33"));
        assert_eq!(dscp_name(0), Some("CS0"));
        assert_eq!(dscp_name(1), Some("LE"));
        assert_eq!(dscp_name(44), Some("VA"));
        // No standard name for these.
        assert_eq!(dscp_name(5), None);
        assert_eq!(dscp_name(63), None);
    }

    #[test]
    fn describe_dscp_includes_name_decimal_and_tos() {
        assert_eq!(describe_dscp(46), "EF (DSCP 46, 0xB8)");
        assert_eq!(describe_dscp(0), "CS0 (DSCP 0, 0x00)");
        assert_eq!(describe_dscp(30), "AF33 (DSCP 30, 0x78)");
        // Unnamed value still shows decimal + TOS byte.
        assert_eq!(describe_dscp(5), "DSCP 5 (0x14)");
    }

    #[test]
    fn dist_describe_reports_names_values_and_percentages() {
        let dist = DscpDist::from_weights(&parse_dscp_weights("ef:60,cs1:40").unwrap()).unwrap();
        assert_eq!(
            dist.describe(),
            "EF (DSCP 46, 0xB8) 60%, CS1 (DSCP 8, 0x20) 40%"
        );
        // Equal split of two -> 50% each.
        let eq = DscpDist::from_weights(&parse_dscp_weights("ef,cs1").unwrap()).unwrap();
        assert_eq!(
            eq.describe(),
            "EF (DSCP 46, 0xB8) 50%, CS1 (DSCP 8, 0x20) 50%"
        );
    }
}
