//! Traceroute functionality module
//!
//! Provides traceroute functionality to measure network path to Cloudflare edge.
//! Uses raw ICMP sockets when available (requires CAP_NET_RAW or root),
//! with fallback to system traceroute command.

use super::network_bind::IpFamily;
use crate::model::{TestEvent, TracerouteHop, TracerouteSummary};
use anyhow::{Context, Result};
use pnet_packet::icmp::IcmpTypes;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// Number of probes per hop
const PROBES_PER_HOP: usize = 3;

/// Timeout for each probe
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Run traceroute to the destination.
///
/// Tries raw ICMP first, falls back to system traceroute if that fails.
/// `family` (from `--ipv4-only` / `--ipv6-only` or the bound source IP's
/// family) restricts which resolved address is probed. When `interface` is set
/// on Linux, `SO_BINDTODEVICE` keeps probes on that NIC.
#[allow(clippy::too_many_arguments)]
pub async fn run_traceroute(
    destination: &str,
    max_hops: u8,
    event_tx: &mpsc::Sender<TestEvent>,
    bind_ip: Option<IpAddr>,
    interface: Option<&str>,
    family: Option<IpFamily>,
    dscp: Option<&super::dscp::DscpDist>,
) -> Result<TracerouteSummary> {
    // Resolve destination to IP, honoring the requested family when set.
    let ip = resolve_destination(destination, family)?;

    // Try raw ICMP first
    match run_icmp_traceroute(&ip, max_hops, event_tx, bind_ip, interface, dscp).await {
        Ok(summary) => return Ok(summary),
        Err(e) => {
            // Send info about fallback
            let _ = event_tx
                .send(TestEvent::Info {
                    message: format!("ICMP traceroute unavailable ({}), using system command", e),
                })
                .await;
        }
    }

    // Fall back to system traceroute. `family` is forwarded so a --ipv4-only /
    // --ipv6-only restriction forces the matching family on the system tool.
    run_system_traceroute(destination, &ip, max_hops, event_tx, bind_ip, interface, family, dscp).await
}

/// Resolve destination hostname to IP address. When `family` is set, return an
/// address of that family; if none exists, error rather than returning an
/// address the run isn't allowed to reach.
fn resolve_destination(destination: &str, family: Option<IpFamily>) -> Result<IpAddr> {
    // Try to parse as IP first
    if let Ok(ip) = destination.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Try DNS resolution
    let addrs: Vec<IpAddr> = format!("{}:0", destination)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {}", destination))?
        .map(|a| a.ip())
        .collect();

    if addrs.is_empty() {
        return Err(anyhow::anyhow!("No addresses found for {}", destination));
    }

    match family {
        Some(f) => addrs.into_iter().find(|a| f.matches(*a)).ok_or_else(|| {
            anyhow::anyhow!("No {} address resolved for {}", f.label(), destination)
        }),
        None => Ok(addrs.into_iter().next().unwrap()),
    }
}

/// Run traceroute using raw ICMP sockets (requires elevated privileges).
async fn run_icmp_traceroute(
    destination: &IpAddr,
    max_hops: u8,
    event_tx: &mpsc::Sender<TestEvent>,
    bind_ip: Option<IpAddr>,
    interface: Option<&str>,
    dscp: Option<&super::dscp::DscpDist>,
) -> Result<TracerouteSummary> {
    // Check if we're dealing with IPv4 - IPv6 traceroute is more complex
    let dest_v4 = match destination {
        IpAddr::V4(v4) => *v4,
        IpAddr::V6(_) => {
            return Err(anyhow::anyhow!(
                "IPv6 traceroute not yet supported via raw sockets"
            ));
        }
    };

    // Refuse a v6 bind against a v4 destination - the socket would error on
    // bind() anyway, so fail fast with a clearer message.
    if let Some(IpAddr::V6(_)) = bind_ip {
        return Err(anyhow::anyhow!(
            "IPv6 source IP is incompatible with IPv4 destination"
        ));
    }

    // Try to create raw ICMP socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .context("Failed to create raw ICMP socket (need CAP_NET_RAW or root)")?;

    // Bind to source IP if requested so probes leave from --interface / --source.
    if let Some(IpAddr::V4(v4)) = bind_ip {
        socket
            .bind(&SocketAddr::new(IpAddr::V4(v4), 0).into())
            .with_context(|| format!("Failed to bind raw ICMP socket to {}", v4))?;
    }

    // Device-bind to the named interface where supported so the kernel can't
    // reroute the probes via another NIC. The raw socket is IPv4-only here, hence
    // is_ipv6 = false. On platforms without device binding this is a no-op; the
    // interface's IPv4 source was already bound via `bind_ip` above.
    if let Some(iface) = interface {
        super::network_bind::bind_socket_to_device(&socket, iface, false).map_err(|e| {
            anyhow::anyhow!("Failed to bind raw ICMP socket to interface {}: {}", iface, e)
        })?;
    }

    // Best-effort DSCP marking on the raw probe socket (IPv4 only here).
    if let Some(dist) = dscp {
        let _ = super::dscp::apply(&socket, dist.select(), false);
    }

    socket.set_read_timeout(Some(PROBE_TIMEOUT))?;
    socket.set_nonblocking(false)?;

    let mut hops = Vec::new();
    let mut completed = false;

    for ttl in 1..=max_hops {
        socket.set_ttl(ttl as u32)?;

        let mut rtts = Vec::new();
        let mut hop_ip: Option<IpAddr> = None;
        let mut timeout = false;

        for probe_num in 0..PROBES_PER_HOP {
            let icmp_id = std::process::id() as u16;
            let icmp_seq = ((ttl as u16) << 8) | (probe_num as u16);

            // Build ICMP echo request packet
            let packet = build_icmp_packet(icmp_id, icmp_seq);

            let dest_addr = SocketAddr::new(IpAddr::V4(dest_v4), 0);

            let start = Instant::now();
            if socket.send_to(&packet, &dest_addr.into()).is_err() {
                continue;
            }

            // Wait for reply using MaybeUninit buffer
            let mut recv_buf: [MaybeUninit<u8>; 512] =
                unsafe { MaybeUninit::uninit().assume_init() };
            match socket.recv_from(&mut recv_buf) {
                Ok((len, from)) => {
                    let rtt = start.elapsed().as_secs_f64() * 1000.0;
                    rtts.push(rtt);

                    // Extract source IP from reply
                    let from_addr: SocketAddr = from.as_socket().unwrap_or(dest_addr);
                    if hop_ip.is_none() {
                        hop_ip = Some(from_addr.ip());
                    }

                    // Check if we've reached the destination
                    if from_addr.ip() == IpAddr::V4(dest_v4) {
                        completed = true;
                    }

                    // Check ICMP type to see if we should continue
                    if len >= 20 + 8 {
                        // IP header + ICMP header
                        // Safe to read since we received at least 28 bytes
                        let icmp_type = unsafe { recv_buf[20].assume_init() };
                        if icmp_type == IcmpTypes::EchoReply.0 {
                            completed = true;
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    timeout = true;
                }
                Err(_) => {
                    timeout = true;
                }
            }
        }

        let hop = TracerouteHop {
            hop_number: ttl,
            ip_address: hop_ip.map(|ip| ip.to_string()),
            hostname: hop_ip.and_then(|ip| resolve_hostname(&ip)),
            rtt_ms: rtts,
            timeout: timeout && hop_ip.is_none(),
        };

        // Send hop event
        let _ = event_tx
            .send(TestEvent::TracerouteHop {
                hop_number: ttl,
                hop: hop.clone(),
            })
            .await;

        hops.push(hop);

        if completed {
            break;
        }
    }

    Ok(TracerouteSummary {
        destination: destination.to_string(),
        hops,
        completed,
    })
}

/// Build an ICMP echo request packet.
fn build_icmp_packet(id: u16, seq: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 64];

    // ICMP header
    packet[0] = IcmpTypes::EchoRequest.0; // Type
    packet[1] = 0; // Code
    packet[2] = 0; // Checksum (will be calculated)
    packet[3] = 0;
    packet[4] = (id >> 8) as u8; // Identifier
    packet[5] = (id & 0xff) as u8;
    packet[6] = (seq >> 8) as u8; // Sequence number
    packet[7] = (seq & 0xff) as u8;

    // Payload (timestamp and padding)
    for i in 8..64 {
        packet[i] = (i - 8) as u8;
    }

    // Calculate checksum
    let checksum = calculate_icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = (checksum & 0xff) as u8;

    packet
}

/// Calculate ICMP checksum.
fn calculate_icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }

    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}

/// Try to resolve an IP address to a hostname.
fn resolve_hostname(_ip: &IpAddr) -> Option<String> {
    // Skip hostname resolution for now to keep it simple
    // In production, we'd want async reverse DNS resolution
    None
}

/// Fall back to system traceroute command.
#[allow(clippy::too_many_arguments)]
async fn run_system_traceroute(
    destination: &str,
    destination_ip: &IpAddr,
    max_hops: u8,
    event_tx: &mpsc::Sender<TestEvent>,
    bind_ip: Option<IpAddr>,
    interface: Option<&str>,
    family: Option<IpFamily>,
    dscp: Option<&super::dscp::DscpDist>,
) -> Result<TracerouteSummary> {
    // Clone strings to avoid lifetime issues with spawn_blocking
    let dest = destination.to_string();
    let dest_ip_str = destination_ip.to_string();

    // Only force an address family when a restriction is in effect
    // (--ipv4-only / --ipv6-only or a bound source IP). Without one we pass no
    // family flag and let the system tool choose, preserving prior behavior on
    // minimal traceroute builds that lack -4/-6.
    let force_v4 = family == Some(IpFamily::V4);
    let force_v6 = family == Some(IpFamily::V6);

    // Determine which command to use based on OS.
    // Note: -n / -d intentionally NOT passed so the OS resolves hostnames.
    // Source IP and interface flags differ per platform:
    //   - tracert (Windows):       -4/-6, -S <srcaddr>, no interface flag.
    //   - traceroute (Linux):      -4/-6, -i <interface>, -s <source>.
    //   - macOS/BSD:               separate traceroute6 binary for IPv6
    //                              (no -6 flag), -i and -s otherwise.
    let (cmd, args): (&'static str, Vec<String>) = if cfg!(target_os = "windows") {
        let mut args = vec!["-h".to_string(), max_hops.to_string()];
        if force_v6 {
            args.push("-6".to_string());
        } else if force_v4 {
            args.push("-4".to_string());
        }
        if let Some(ip) = bind_ip {
            args.push("-S".to_string());
            args.push(ip.to_string());
        }
        args.push(dest.clone());
        ("tracert", args)
    } else {
        // macOS and the BSDs ship a dedicated `traceroute6` rather than a
        // `-6` flag on `traceroute`; Linux's traceroute takes -4/-6 directly.
        let uses_separate_v6_binary = cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd"
        ));

        let cmd = if force_v6 && uses_separate_v6_binary {
            "traceroute6"
        } else {
            "traceroute"
        };

        let mut args = vec![
            "-m".to_string(),
            max_hops.to_string(),
            "-q".to_string(),
            "3".to_string(),
        ];
        if !uses_separate_v6_binary {
            if force_v6 {
                args.push("-6".to_string());
            } else if force_v4 {
                args.push("-4".to_string());
            }
        }
        if let Some(iface) = interface {
            args.push("-i".to_string());
            args.push(iface.to_string());
        }
        if let Some(ip) = bind_ip {
            args.push("-s".to_string());
            args.push(ip.to_string());
        }
        // traceroute(8) takes the full TOS byte via -t (Windows tracert has no
        // equivalent flag, so the marking is skipped there). The system command
        // is one process, so a single weighted draw applies to the whole run.
        if let Some(dist) = dscp {
            args.push("-t".to_string());
            args.push(super::dscp::tos_byte(dist.select()).to_string());
        }
        args.push(dest.clone());
        (cmd, args)
    };

    let output = tokio::task::spawn_blocking(move || Command::new(cmd).args(&args).output())
        .await
        .context("Traceroute task failed")?
        .context("Failed to execute traceroute command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "traceroute exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hops = parse_traceroute_output(&stdout, event_tx).await;

    let completed = hops
        .last()
        .map(|h| h.ip_address.as_deref() == Some(&dest_ip_str))
        .unwrap_or(false);

    Ok(TracerouteSummary {
        destination: destination.to_string(),
        hops,
        completed,
    })
}

/// Parse traceroute command output into hop structures.
async fn parse_traceroute_output(
    output: &str,
    event_tx: &mpsc::Sender<TestEvent>,
) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Skip header lines
        if line.is_empty()
            || line.starts_with("traceroute")
            || line.starts_with("Tracing")
            || line.contains("hops max")
        {
            continue;
        }

        // Parse hop line (format varies by OS)
        // Linux: " 1  192.168.1.1  0.123 ms  0.456 ms  0.789 ms"
        // macOS: " 1  192.168.1.1  0.123 ms  0.456 ms  0.789 ms"
        // Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"

        if let Some(hop) = parse_hop_line(line) {
            let _ = event_tx
                .send(TestEvent::TracerouteHop {
                    hop_number: hop.hop_number,
                    hop: hop.clone(),
                })
                .await;
            hops.push(hop);
        }
    }

    hops
}

/// Parse a single hop line from traceroute output.
///
/// Handles three formats:
/// - Linux/macOS with DNS:    `1  host.name (1.2.3.4)  0.5 ms 0.4 ms 0.6 ms`
/// - Linux/macOS without DNS: `1  1.2.3.4  0.5 ms 0.4 ms 0.6 ms`
/// - Windows with DNS:        `1  <1 ms <1 ms <1 ms  host.name [1.2.3.4]`
fn parse_hop_line(line: &str) -> Option<TracerouteHop> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    let hop_number: u8 = parts.first()?.parse().ok()?;

    if parts.iter().skip(1).all(|p| *p == "*") {
        return Some(TracerouteHop {
            hop_number,
            ip_address: None,
            hostname: None,
            rtt_ms: Vec::new(),
            timeout: true,
        });
    }

    let mut ip_address: Option<String> = None;
    let mut hostname: Option<String> = None;
    let mut rtts: Vec<f64> = Vec::new();
    let mut prev_candidate: Option<String> = None;

    for part in parts.iter().skip(1) {
        if *part == "ms" {
            continue;
        }

        // Numeric RTT (handles plain `0.5`, `0.5ms`, and Windows `<1`).
        let cleaned = part.trim_start_matches('<').trim_end_matches("ms");
        if let Ok(rtt) = cleaned.parse::<f64>() {
            rtts.push(rtt);
            prev_candidate = None;
            continue;
        }

        let was_wrapped = part.starts_with('(') || part.starts_with('[');
        let stripped = part
            .trim_start_matches(['(', '['])
            .trim_end_matches([')', ']']);

        if stripped.parse::<IpAddr>().is_ok() {
            if ip_address.is_none() {
                ip_address = Some(stripped.to_string());
                if was_wrapped {
                    if let Some(prev) = prev_candidate.take() {
                        if prev != stripped {
                            hostname = Some(prev);
                        }
                    }
                }
            }
            prev_candidate = None;
        } else {
            // Not an IP, not a number: candidate hostname for the next wrapped IP.
            prev_candidate = Some(part.to_string());
        }
    }

    if ip_address.is_none() && rtts.is_empty() {
        return None;
    }

    Some(TracerouteHop {
        hop_number,
        ip_address,
        hostname,
        rtt_ms: rtts,
        timeout: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_with_hostname() {
        let line = " 1  host.example.com (1.2.3.4)  0.5 ms  0.4 ms  0.6 ms";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.hop_number, 1);
        assert_eq!(hop.ip_address.as_deref(), Some("1.2.3.4"));
        assert_eq!(hop.hostname.as_deref(), Some("host.example.com"));
        assert_eq!(hop.rtt_ms, vec![0.5, 0.4, 0.6]);
        assert!(!hop.timeout);
    }

    #[test]
    fn parses_linux_without_dns() {
        let line = " 2  1.2.3.4  0.5 ms 0.4 ms 0.6 ms";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ip_address.as_deref(), Some("1.2.3.4"));
        assert_eq!(hop.hostname, None);
        assert_eq!(hop.rtt_ms, vec![0.5, 0.4, 0.6]);
    }

    #[test]
    fn parses_linux_when_hostname_equals_ip() {
        // When DNS fails, traceroute often shows `ip (ip)` with both being identical.
        let line = " 3  10.0.0.1 (10.0.0.1)  5.2 ms 4.8 ms 5.1 ms";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ip_address.as_deref(), Some("10.0.0.1"));
        assert_eq!(hop.hostname, None, "hostname should be elided when same as ip");
    }

    #[test]
    fn parses_timeout_line() {
        let line = " 5  * * *";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ip_address, None);
        assert_eq!(hop.hostname, None);
        assert!(hop.timeout);
        assert!(hop.rtt_ms.is_empty());
    }

    #[test]
    fn parses_windows_with_hostname() {
        let line = "  1    <1 ms    <1 ms    <1 ms  router.local [192.168.1.1]";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ip_address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hop.hostname.as_deref(), Some("router.local"));
        assert_eq!(hop.rtt_ms, vec![1.0, 1.0, 1.0]);
    }

    #[test]
    fn first_ip_wins_on_multi_router_hop() {
        // Some hops have two routers responding; we keep the first IP/hostname pair.
        let line = " 5  a.example.com (1.1.1.1)  260.2 ms b.example.com (2.2.2.2)  260.1 ms 260.0 ms";
        let hop = parse_hop_line(line).unwrap();
        assert_eq!(hop.ip_address.as_deref(), Some("1.1.1.1"));
        assert_eq!(hop.hostname.as_deref(), Some("a.example.com"));
        assert_eq!(hop.rtt_ms.len(), 3);
    }
}
