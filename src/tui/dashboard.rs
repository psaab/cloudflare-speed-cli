use ratatui::{
    layout::{Constraint, Direction, Layout, Margin, Rect},
    style::Color,
    style::Style,
    symbols,
    text::{Line, Span},
    widgets::{
        Axis, Block, Borders, Dataset, GraphType, Paragraph, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Sparkline,
    },
    Frame,
};

use super::charts;
use super::log_style;
use super::state::{push_wrapped_status_kv, UiState, REDACTED_PLACEHOLDER};
use std::borrow::Cow;

/// Returns `REDACTED_PLACEHOLDER` when `hide` is true, otherwise `value` or `"-"` for `None`.
/// Used to conceal identifying network info (IP, MAC, SSID, ISP, location) for
/// screenshot/demo sharing without altering stored history.
fn show_or_redact<'a>(value: Option<&'a str>, hide: bool) -> &'a str {
    if hide {
        REDACTED_PLACEHOLDER
    } else {
        value.unwrap_or("-")
    }
}

/// Display value for an "External IPv4"/"External IPv6" panel row: the probe
/// result when available, otherwise the meta client IP. The fallback must stay
/// family-checked — a `-4`/`-6` run skips the other family's probe, and the
/// client IP would otherwise show up on the wrong row.
fn external_ip_for_family<'a>(
    external: Option<&'a str>,
    meta_ip: Option<&'a str>,
    want_ipv4: bool,
) -> Option<&'a str> {
    external.or_else(|| {
        meta_ip.filter(|ip| {
            ip.parse::<std::net::IpAddr>()
                .map(|addr| addr.is_ipv4() == want_ipv4)
                .unwrap_or(false)
        })
    })
}

/// Redacts identifying info from a single Test Activity log line.
///
/// Strategy: substring-replace values the engine already populated into `state`
/// (covers IP/ASN/ISP/server/colo/network/interface). Then pattern-replace any
/// remaining IPv4 dotted-quads (covers traceroute hops and IP-comparison IPs
/// that aren't in `state`). Cheap no-op when redaction is off — returns the
/// borrowed input without allocating.
fn redact_log_line<'a>(line: &'a str, state: &UiState) -> Cow<'a, str> {
    if !state.hide_network_info {
        return Cow::Borrowed(line);
    }

    let mut needles: Vec<&str> = [
        state.external_ipv6.as_deref(),
        state.external_ipv4.as_deref(),
        state.ip.as_deref(),
        state.interface_mac.as_deref(),
        state.as_org.as_deref(),
        state.network_name.as_deref(),
        state.interface_name.as_deref(),
        state.server.as_deref(),
        state.colo.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|v| v.len() >= 2 && *v != "-")
    .collect();
    // Longest-first so e.g. "fe80::1234" isn't half-replaced by a shorter
    // "1234" needle that snuck in.
    needles.sort_by_key(|v| std::cmp::Reverse(v.len()));

    let mut s = line.to_string();
    for needle in needles {
        s = replace_token(&s, needle, REDACTED_PLACEHOLDER);
    }
    s = redact_ipv4_in(&s);
    Cow::Owned(s)
}

/// `haystack.replace(needle, replacement)` but only at alphanumeric word
/// boundaries, so an ASN like `13335` doesn't smear into a throughput value
/// like `13335.7 Mbps`.
fn replace_token(haystack: &str, needle: &str, replacement: &str) -> String {
    let mut out = String::with_capacity(haystack.len());
    let mut last = 0;
    for (i, _) in haystack.match_indices(needle) {
        let before = haystack[..i].chars().next_back();
        let after = haystack[i + needle.len()..].chars().next();
        let is_boundary = |c: Option<char>| match c {
            None => true,
            Some(c) => !c.is_alphanumeric(),
        };
        if is_boundary(before) && is_boundary(after) {
            out.push_str(&haystack[last..i]);
            out.push_str(replacement);
            last = i + needle.len();
        }
    }
    out.push_str(&haystack[last..]);
    out
}

/// Replaces every IPv4 dotted-quad in `s` with `REDACTED_PLACEHOLDER`.
/// Conservative: requires four 0–255 octets and rejects sequences that are part
/// of a longer dotted/digit run (so `1.23ms` and `1.2.3.4.5` don't match).
fn redact_ipv4_in(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            if let Some(end) = ipv4_match_end(bytes, i) {
                out.push_str(REDACTED_PLACEHOLDER);
                i = end;
                continue;
            }
        }
        let cp_end = next_utf8_char_end(bytes, i);
        out.push_str(std::str::from_utf8(&bytes[i..cp_end]).unwrap_or(""));
        i = cp_end;
    }
    out
}

fn ipv4_match_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    for octet_idx in 0..4 {
        if octet_idx > 0 {
            if bytes.get(i).copied() != Some(b'.') {
                return None;
            }
            i += 1;
        }
        let octet_start = i;
        while i < bytes.len() && (i - octet_start) < 3 && bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i == octet_start {
            return None;
        }
        let octet: u32 = std::str::from_utf8(&bytes[octet_start..i])
            .ok()?
            .parse()
            .ok()?;
        if octet > 255 {
            return None;
        }
    }
    // Reject when extending into a longer number / 5th octet so we don't
    // grab the leading 4 octets of `1.2.3.4.5`.
    if let Some(&next) = bytes.get(i) {
        if next.is_ascii_digit() {
            return None;
        }
        if next == b'.' {
            if let Some(&peek) = bytes.get(i + 1) {
                if peek.is_ascii_digit() {
                    return None;
                }
            }
        }
    }
    Some(i)
}

fn next_utf8_char_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() && (bytes[i] & 0xC0) == 0x80 {
        i += 1;
    }
    i
}

/// Helper function to get the maximum y value from a series of points
pub fn max_y(points: &[(f64, f64)]) -> f64 {
    points.iter().map(|(_, y)| *y).fold(0.0, |a, b| a.max(b))
}

fn udp_split_bar(sent: u64, received: u64, width: usize) -> Line<'static> {
    let safe_sent = sent.max(1);
    let safe_received = received.min(safe_sent);
    let lost = safe_sent.saturating_sub(safe_received);
    // Ensure any loss shows at least one red segment
    let lost_units = if lost > 0 {
        (width as f64 * lost as f64 / safe_sent as f64).ceil().max(1.0) as usize
    } else {
        0
    };
    let ok_units = width.saturating_sub(lost_units);

    let ok_part = "=".repeat(ok_units);
    let lost_part = "x".repeat(lost_units);

    Line::from(vec![
        Span::styled("UDP split: ", Style::default().fg(Color::Gray)),
        Span::raw("["),
        Span::styled(ok_part, Style::default().fg(Color::Green)),
        Span::styled(lost_part, Style::default().fg(Color::Red)),
        Span::raw("] "),
        Span::styled(format!("ok {} lost {}", safe_received, lost), Style::default().fg(Color::Gray)),
    ])
}

/// Get color for quality label based on loss severity
fn quality_label_color(label: &str) -> Color {
    match label {
        "Excellent" | "Good" => Color::Green,
        "Acceptable" => Color::Yellow,
        "Poor" => Color::Magenta,
        "Bad" => Color::Red,
        _ => Color::Gray,
    }
}

pub fn draw_dashboard(area: Rect, f: &mut Frame, state: &UiState) {
    // Small terminal: keep the compact dashboard (gauges + sparklines).
    // Large terminal: show full charts (like the website) alongside the live cards.
    // Total fixed-height rows in the full dashboard:
    //   13 (throughput) + 10 (latency) + 3 (UDP) + 5 (status) = 31
    // We need at least ~3 rows for the Network Info / Test Activity row,
    // so fall back to the compact layout below 34 rows. Otherwise the
    // Status panel gets clipped at the bottom.
    if area.height < 34 {
        return draw_dashboard_compact(area, f, state);
    }

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Length(13), // Throughput charts row with metrics (side-by-side)
                Constraint::Length(10), // Latency box plots with metrics below (idle + loaded DL + loaded UL)
                Constraint::Length(3),  // Packet loss (UDP) row
                Constraint::Min(0),     // Network Information + Keyboard Shortcuts (side-by-side)
                Constraint::Length(5),  // Status row (full width at bottom)
            ]
            .as_ref(),
        )
        .split(area);

    // Throughput charts side-by-side: DL left, UL right
    let thr_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(main[0]);

    // Download throughput chart (left) - only show when download phase has data
    if state.dl_phase_start.is_some() && !state.dl_points.is_empty() {
        // Calculate x bounds only for download points
        let dl_x_max = state.dl_points.last().map(|(x, _)| *x).unwrap_or(0.0);
        let dl_x_min = state.dl_points.first().map(|(x, _)| *x).unwrap_or(0.0);

        let y_dl_max = max_y(&state.dl_points).max(10.0);
        let y_dl_max = (y_dl_max * 1.10).min(10_000.0);

        // Use all download points (they're already filtered to download phase)
        let dl_ds = Dataset::default()
            .graph_type(GraphType::Line)
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Green))
            .data(&state.dl_points);

        let dl_values: Vec<f64> = state.dl_points.iter().map(|(_, y)| *y).collect();
        let dl_metrics = crate::metrics::compute_metrics(&dl_values);
        // Use the computed mean from metrics for the title to match what's shown below
        let dl_avg = dl_metrics
            .map(|(mean, _, _, _)| mean)
            .unwrap_or(state.dl_avg_mbps);
        let dl_title = Line::from(vec![
            Span::raw("Download (inst "),
            Span::styled(
                format!("{:.0}", state.dl_mbps),
                Style::default().fg(Color::Green),
            ),
            Span::raw(" / avg "),
            Span::styled(format!("{:.0}", dl_avg), Style::default().fg(Color::Green)),
            Span::raw(" Mbps)"),
        ]);
        charts::render_chart_with_metrics_inside(
            f,
            thr_row[0],
            vec![dl_ds],
            Axis::default().bounds([dl_x_min, dl_x_max.max(1.0)]),
            Axis::default().title("Mbps").bounds([0.0, y_dl_max]),
            dl_title,
            dl_metrics,
            Color::Green,
        );
    } else {
        // Show empty placeholder when download hasn't started
        let empty_chart = Paragraph::new("Waiting for download phase...").block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::raw("Download (inst "),
                    Span::styled(
                        format!("{:.0}", state.dl_mbps),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" / avg "),
                    Span::styled(
                        format!("{:.0}", state.dl_avg_mbps),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" Mbps)"),
                ])),
        );
        f.render_widget(empty_chart, thr_row[0]);
    }

    // Upload throughput chart (right) - only show when upload phase has data
    if state.ul_phase_start.is_some() && !state.ul_points.is_empty() {
        // Calculate x bounds only for upload points
        let ul_x_max = state.ul_points.last().map(|(x, _)| *x).unwrap_or(0.0);
        let ul_x_min = state.ul_points.first().map(|(x, _)| *x).unwrap_or(0.0);

        let y_ul_max = max_y(&state.ul_points).max(10.0);
        let y_ul_max = (y_ul_max * 1.10).min(10_000.0);

        // Use all upload points (they're already filtered to upload phase)
        let ul_ds = Dataset::default()
            .graph_type(GraphType::Line)
            .marker(symbols::Marker::Braille)
            .style(Style::default().fg(Color::Cyan))
            .data(&state.ul_points);

        let ul_values: Vec<f64> = state.ul_points.iter().map(|(_, y)| *y).collect();
        let ul_metrics = crate::metrics::compute_metrics(&ul_values);
        // Use the computed mean from metrics for the title to match what's shown below
        let ul_avg = ul_metrics
            .map(|(mean, _, _, _)| mean)
            .unwrap_or(state.ul_avg_mbps);
        let ul_title = Line::from(vec![
            Span::raw("Upload (inst "),
            Span::styled(
                format!("{:.0}", state.ul_mbps),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" / avg "),
            Span::styled(format!("{:.0}", ul_avg), Style::default().fg(Color::Cyan)),
            Span::raw(" Mbps)"),
        ]);
        charts::render_chart_with_metrics_inside(
            f,
            thr_row[1],
            vec![ul_ds],
            Axis::default().bounds([ul_x_min, ul_x_max.max(1.0)]),
            Axis::default().title("Mbps").bounds([0.0, y_ul_max]),
            ul_title,
            ul_metrics,
            Color::Cyan,
        );
    } else {
        // Show empty placeholder when upload hasn't started
        let empty_chart = Paragraph::new("Waiting for upload phase...").block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(vec![
                    Span::raw("Upload (inst "),
                    Span::styled(
                        format!("{:.0}", state.ul_mbps),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" / avg "),
                    Span::styled(
                        format!("{:.0}", state.ul_avg_mbps),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" Mbps)"),
                ])),
        );
        f.render_widget(empty_chart, thr_row[1]);
    }

    // Latency box plots: Idle, Loaded DL, Loaded UL
    let lat_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ]
            .as_ref(),
        )
        .split(main[1]);

    // Idle latency
    if !state.idle_latency_samples.is_empty() {
        // Use the same median calculation as the metrics below
        let median = crate::metrics::compute_metrics(&state.idle_latency_samples)
            .map(|(_, med, _, _)| med)
            .unwrap_or(f64::NAN);
        let jitter = crate::metrics::compute_jitter(&state.idle_latency_samples);
        let title = Line::from(format!("Idle Latency ({:.0}ms)", median));
        charts::render_box_plot_with_metrics_inside(
            f,
            lat_row[0],
            &state.idle_latency_samples,
            title,
            None,
            jitter,
            None,
        );
    } else {
        let empty = Paragraph::new("Waiting for data...")
            .block(Block::default().borders(Borders::ALL).title("Idle Latency"));
        f.render_widget(empty, lat_row[0]);
    }

    // Download latency
    if !state.loaded_dl_latency_samples.is_empty() {
        // Use the same median calculation as the metrics below
        let median = crate::metrics::compute_metrics(&state.loaded_dl_latency_samples)
            .map(|(_, med, _, _)| med)
            .unwrap_or(f64::NAN);
        let jitter = crate::metrics::compute_jitter(&state.loaded_dl_latency_samples);
        let title = Line::from(vec![
            Span::raw("Latency Download ("),
            Span::styled(
                format!("{:.0}ms", median),
                Style::default().fg(Color::Green),
            ),
            Span::raw(")"),
        ]);
        charts::render_box_plot_with_metrics_inside(
            f,
            lat_row[1],
            &state.loaded_dl_latency_samples,
            title,
            Some(Color::Green),
            jitter,
            None,
        );
    } else {
        let empty = Paragraph::new("Waiting for data...").block(
            Block::default()
                .borders(Borders::ALL)
                .title("Latency Download"),
        );
        f.render_widget(empty, lat_row[1]);
    }

    // Upload latency
    if !state.loaded_ul_latency_samples.is_empty() {
        // Use the same median calculation as the metrics below
        let median = crate::metrics::compute_metrics(&state.loaded_ul_latency_samples)
            .map(|(_, med, _, _)| med)
            .unwrap_or(f64::NAN);
        let jitter = crate::metrics::compute_jitter(&state.loaded_ul_latency_samples);
        let title = Line::from(vec![
            Span::raw("Latency Upload ("),
            Span::styled(format!("{:.0}ms", median), Style::default().fg(Color::Cyan)),
            Span::raw(")"),
        ]);
        charts::render_box_plot_with_metrics_inside(
            f,
            lat_row[2],
            &state.loaded_ul_latency_samples,
            title,
            Some(Color::Cyan),
            jitter,
            None,
        );
    } else {
        let empty = Paragraph::new("Waiting for data...").block(
            Block::default()
                .borders(Borders::ALL)
                .title("Latency Upload"),
        );
        f.render_widget(empty, lat_row[2]);
    }

    // Packet loss row (full width) with live progress during measurement
    let (udp_sent, udp_received, udp_total, udp_latest_rtt) = if state.udp_loss_total > 0 {
        (
            state.udp_loss_sent,
            state.udp_loss_received,
            state.udp_loss_total,
            state.udp_loss_latest_rtt_ms,
        )
    } else if let Some(exp) = state
        .last_result
        .as_ref()
        .and_then(|r| r.experimental_udp.as_ref())
    {
        (
            exp.latency.sent,
            exp.latency.received,
            exp.latency.sent,
            exp.latency.median_ms,
        )
    } else {
        (0, 0, 0, None)
    };
    let udp_loss_pct = if udp_sent == 0 {
        0.0
    } else {
        ((udp_sent.saturating_sub(udp_received)) as f64) * 100.0 / udp_sent as f64
    };
    let udp_status = if state.phase == crate::model::Phase::PacketLoss {
        "running"
    } else if udp_sent > 0 {
        "complete"
    } else {
        "waiting"
    };
    let udp_block = Block::default()
        .borders(Borders::ALL)
        .title("Packet Loss (UDP/TURN)");
    let udp_inner = udp_block.inner(main[2]);
    f.render_widget(udp_block, main[2]);

    if let Some(err) = state
        .last_result
        .as_ref()
        .and_then(|r| r.udp_error.as_ref())
    {
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Packet loss probe failed: ", Style::default().fg(Color::Gray)),
                Span::styled(err.as_str(), Style::default().fg(Color::Yellow)),
            ])),
            udp_inner,
        );
    } else if udp_total > 0 || udp_sent > 0 {
        let safe_total = udp_total.max(udp_sent).max(1);
        let safe_received = udp_received.min(udp_sent);
        let lost = udp_sent.saturating_sub(safe_received);
        let pending = safe_total.saturating_sub(udp_sent);

        let rtt_str = udp_latest_rtt
            .map(|v| format!("{:.0}ms", v))
            .unwrap_or_else(|| "-".to_string());

        // Get quality label, MOS, jitter, and reorder info from completed result
        let (quality_label, mos_str, jitter_str, reorder_str) = state
            .last_result
            .as_ref()
            .and_then(|r| r.experimental_udp.as_ref())
            .map(|exp| {
                let label = exp.quality_label.as_str();
                let mos = exp.mos.map(|m| format!("MOS {:.1}", m)).unwrap_or_default();
                let jitter = exp.latency.jitter_ms.map(|j| format!("jitter {:.1}ms", j)).unwrap_or_default();
                let reorder = format!("reorder {:.1}%", exp.out_of_order_pct);
                (label, mos, jitter, reorder)
            })
            .unwrap_or(("", String::new(), String::new(), String::new()));

        // Calculate text width before the bar
        let mut pre_bar_width: usize = 0;
        pre_bar_width += udp_status.len() + 1; // status + space
        if !quality_label.is_empty() {
            pre_bar_width += quality_label.len();
            if !mos_str.is_empty() {
                pre_bar_width += 2 + mos_str.len() + 2; // " (" + mos + ") "
            } else {
                pre_bar_width += 1; // space
            }
        }
        let loss_str = format!("loss {:.1}%", udp_loss_pct);
        let rtt_display = format!("rtt {}", rtt_str);
        pre_bar_width += loss_str.len() + 1 + rtt_display.len(); // loss + space + rtt
        if !jitter_str.is_empty() {
            pre_bar_width += 1 + jitter_str.len();
        }
        if !reorder_str.is_empty() && state.phase != crate::model::Phase::PacketLoss {
            pre_bar_width += 1 + reorder_str.len();
        }
        pre_bar_width += 2; // "  " before bar

        // Calculate text width after the bar
        let ok_str = format!("ok {}", safe_received);
        let lost_str = format!("lost {}", lost);
        let mut post_bar_width: usize = 2 + ok_str.len() + 1 + lost_str.len(); // "  " + ok + " " + lost
        if pending > 0 {
            post_bar_width += format!(" pending {}", pending).len();
        }

        // Calculate bar width from remaining space
        let total_text_width = pre_bar_width + post_bar_width;
        let available_width = udp_inner.width as usize;
        let bar_width = if available_width > total_text_width + 5 {
            available_width - total_text_width
        } else {
            10 // minimum bar width
        };

        // Ensure any loss shows at least one red segment
        let lost_units = if lost > 0 {
            ((lost as f64 / safe_total as f64) * bar_width as f64).ceil().max(1.0) as usize
        } else {
            0
        };
        let recv_units = ((safe_received as f64 / safe_total as f64) * bar_width as f64).floor() as usize;
        let pending_units = bar_width.saturating_sub(recv_units + lost_units);

        let bar_recv = "█".repeat(recv_units);
        let bar_lost = "█".repeat(lost_units);
        let bar_pending = "░".repeat(pending_units);

        let mut spans = vec![
            Span::styled(udp_status, Style::default().fg(Color::Yellow)),
            Span::raw(" "),
        ];

        // Show quality label and MOS when test is complete
        if !quality_label.is_empty() {
            let label_color = quality_label_color(quality_label);
            spans.push(Span::styled(quality_label, Style::default().fg(label_color)));
            if !mos_str.is_empty() {
                spans.push(Span::raw(" ("));
                spans.push(Span::styled(&mos_str, Style::default().fg(label_color)));
                spans.push(Span::raw(") "));
            } else {
                spans.push(Span::raw(" "));
            }
        }

        spans.extend(vec![
            Span::styled(
                loss_str,
                Style::default().fg(if udp_loss_pct == 0.0 { Color::Green } else if udp_loss_pct < 2.5 { Color::Yellow } else { Color::Red }),
            ),
            Span::raw(" "),
            Span::styled(rtt_display, Style::default().fg(Color::Gray)),
        ]);

        // Add jitter and reorder when available
        if !jitter_str.is_empty() {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(&jitter_str, Style::default().fg(Color::Gray)));
        }
        if !reorder_str.is_empty() && state.phase != crate::model::Phase::PacketLoss {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(&reorder_str, Style::default().fg(Color::Gray)));
        }

        spans.extend(vec![
            Span::raw("  "),
            Span::styled(bar_recv, Style::default().fg(Color::Green)),
            Span::styled(bar_lost, Style::default().fg(Color::Red)),
            Span::styled(bar_pending, Style::default().fg(Color::DarkGray)),
            Span::raw("  "),
            Span::styled(ok_str, Style::default().fg(Color::Green)),
            Span::raw(" "),
            Span::styled(lost_str, Style::default().fg(Color::Red)),
        ]);

        if pending > 0 {
            spans.push(Span::styled(format!(" pending {}", pending), Style::default().fg(Color::DarkGray)));
        }

        f.render_widget(
            Paragraph::new(Line::from(spans)),
            udp_inner,
        );
    } else {
        let msg = if state.phase == crate::model::Phase::PacketLoss {
            "Packet loss probe starting..."
        } else {
            "Packet loss probe starts after upload phase..."
        };
        f.render_widget(Paragraph::new(msg), udp_inner);
    }

    // Network Information and Keyboard Shortcuts side-by-side
    let info_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(main[3]);

    // Network Information panel (left)

    // Determine IP version
    let ip_version = state
        .ip
        .as_deref()
        .map(|ip| if ip.contains(':') { "IPv6" } else { "IPv4" })
        .unwrap_or("-");

    let ip_version_color = match ip_version {
        "IPv4" => Color::Green,
        "IPv6" => Color::Cyan,
        _ => Color::Gray,
    };

    let is_wireless = state.is_wireless.unwrap_or(false);
    let (link_label, link_color) = if is_wireless {
        ("Wireless", Color::Yellow)
    } else {
        ("Wired", Color::Green)
    };

    let hide = state.hide_network_info;
    let network_display = if hide {
        REDACTED_PLACEHOLDER.to_string()
    } else {
        state
            .network_name
            .as_deref()
            .or_else(|| state.interface_name.as_deref())
            .unwrap_or("-")
            .to_string()
    };

    let mut network_lines = vec![
        Line::from(vec![
            Span::styled("Connected via: ", Style::default().fg(Color::Gray)),
            Span::styled(ip_version, Style::default().fg(ip_version_color)),
        ]),
        Line::from(vec![
            Span::styled("Interface: ", Style::default().fg(Color::Gray)),
            Span::raw(show_or_redact(state.interface_name.as_deref(), hide).to_string()),
            Span::raw(" ("),
            Span::styled(link_label, Style::default().fg(link_color)),
            Span::raw(")"),
        ]),
        Line::from(vec![
            Span::styled("Network: ", Style::default().fg(Color::Gray)),
            Span::raw(network_display),
        ]),
        Line::from(vec![
            Span::styled("MAC address: ", Style::default().fg(Color::Gray)),
            Span::styled(
                show_or_redact(state.interface_mac.as_deref(), hide).to_string(),
                Style::default().fg(Color::Magenta),
            ),
        ]),
    ];

    // Only show Certificate line if a certificate is set
    if let Some(ref cert_filename) = state.certificate_filename {
        network_lines.push(Line::from(vec![
            Span::styled("Certificate: ", Style::default().fg(Color::Gray)),
            Span::styled(cert_filename.clone(), Style::default().fg(Color::Cyan)),
        ]));
    }

    // Only show Proxy line if a proxy is set
    if let Some(ref proxy_url) = state.proxy_url {
        network_lines.push(Line::from(vec![
            Span::styled("Proxy: ", Style::default().fg(Color::Gray)),
            Span::styled(proxy_url.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    // Only show DSCP line if marking is enabled
    if let Some(ref dscp) = state.dscp_label {
        network_lines.push(Line::from(vec![
            Span::styled("DSCP: ", Style::default().fg(Color::Gray)),
            Span::styled(dscp.clone(), Style::default().fg(Color::Yellow)),
        ]));
    }

    network_lines.push(Line::from(vec![
        Span::styled("Server location: ", Style::default().fg(Color::Gray)),
        Span::styled(
            show_or_redact(state.server.as_deref(), hide).to_string(),
            Style::default().fg(Color::Cyan),
        ),
    ]));

    // "Your network: ORG (ASNXXXX)" — split so we can dim the AS number.
    let mut your_network: Vec<Span<'static>> = vec![Span::styled(
        "Your network: ",
        Style::default().fg(Color::Gray),
    )];
    if hide {
        your_network.push(Span::styled(
            REDACTED_PLACEHOLDER.to_string(),
            Style::default().fg(Color::Cyan),
        ));
    } else {
        match (state.as_org.as_deref(), state.asn.as_deref()) {
            (Some(org), Some(asn)) => {
                your_network.push(Span::styled(org.to_string(), Style::default().fg(Color::Cyan)));
                your_network.push(Span::raw(" ("));
                your_network.push(Span::styled(
                    format!("AS{}", asn),
                    Style::default().fg(Color::Magenta),
                ));
                your_network.push(Span::raw(")"));
            }
            (Some(org), None) => {
                your_network.push(Span::styled(org.to_string(), Style::default().fg(Color::Cyan)));
            }
            (None, Some(asn)) => {
                your_network.push(Span::styled(
                    format!("AS{}", asn),
                    Style::default().fg(Color::Magenta),
                ));
            }
            (None, None) => your_network.push(Span::raw("-")),
        }
    }
    network_lines.push(Line::from(your_network));

    network_lines.extend(vec![
        Line::from(vec![
            Span::styled("External IPv4: ", Style::default().fg(Color::Gray)),
            Span::styled(
                show_or_redact(
                    external_ip_for_family(
                        state.external_ipv4.as_deref(),
                        state.ip.as_deref(),
                        true,
                    ),
                    hide,
                )
                .to_string(),
                Style::default().fg(Color::Green),
            ),
        ]),
        Line::from(vec![
            Span::styled("External IPv6: ", Style::default().fg(Color::Gray)),
            Span::styled(
                show_or_redact(
                    external_ip_for_family(
                        state.external_ipv6.as_deref(),
                        state.ip.as_deref(),
                        false,
                    ),
                    hide,
                )
                .to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]),
    ]);

    // Diagnostic results at the end, before the source link
    let has_diagnostics = state.dns_summary.is_some()
        || state.tls_summary.is_some()
        || state.ip_comparison.is_some()
        || state.traceroute_summary.is_some();

    if has_diagnostics {
        network_lines.push(Line::from("")); // Separator

        if let Some(ref dns) = state.dns_summary {
            network_lines.push(Line::from(vec![
                Span::styled("DNS resolution: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{:.2}ms", dns.resolution_time_ms),
                    Style::default().fg(Color::Yellow),
                ),
            ]));
        }

        if let Some(ref tls) = state.tls_summary {
            network_lines.push(Line::from(vec![
                Span::styled("TLS handshake: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    format!("{:.2}ms", tls.handshake_time_ms),
                    Style::default().fg(Color::Yellow),
                ),
                Span::raw(" "),
                Span::styled(
                    tls.protocol_version.as_deref().unwrap_or("-").to_string(),
                    Style::default().fg(Color::Green),
                ),
            ]));
        }

        if let Some(ref cmp) = state.ip_comparison {
            let mut cmp_spans: Vec<Span<'static>> = vec![Span::styled(
                "IPv4 vs IPv6: ",
                Style::default().fg(Color::Gray),
            )];
            cmp_spans.push(Span::styled("v4:", Style::default().fg(Color::Gray)));
            match cmp.ipv4_result.as_ref() {
                Some(r) if r.available => cmp_spans.push(Span::styled(
                    format!("{:.1}Mbps", r.download_mbps),
                    Style::default().fg(Color::Green),
                )),
                Some(_) => cmp_spans.push(Span::styled("N/A", Style::default().fg(Color::Red))),
                None => cmp_spans.push(Span::raw("-")),
            }
            cmp_spans.push(Span::raw(" "));
            cmp_spans.push(Span::styled("v6:", Style::default().fg(Color::Gray)));
            match cmp.ipv6_result.as_ref() {
                Some(r) if r.available => cmp_spans.push(Span::styled(
                    format!("{:.1}Mbps", r.download_mbps),
                    Style::default().fg(Color::Cyan),
                )),
                Some(_) => cmp_spans.push(Span::styled("N/A", Style::default().fg(Color::Red))),
                None => cmp_spans.push(Span::raw("-")),
            }
            network_lines.push(Line::from(cmp_spans));
        }

        if let Some(ref tr) = state.traceroute_summary {
            let (status, status_color) = if tr.completed {
                ("complete", Color::Green)
            } else {
                ("partial", Color::Yellow)
            };
            network_lines.push(Line::from(vec![
                Span::styled("Traceroute: ", Style::default().fg(Color::Gray)),
                Span::styled(
                    tr.hops.len().to_string(),
                    Style::default().fg(Color::Cyan),
                ),
                Span::styled(" hops (", Style::default().fg(Color::Gray)),
                Span::styled(status, Style::default().fg(status_color)),
                Span::styled(")", Style::default().fg(Color::Gray)),
            ]));
        }
    }

    network_lines.extend(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("Source: ", Style::default().fg(Color::Gray)),
            Span::styled(
                "https://speed.cloudflare.com/",
                Style::default().fg(Color::Blue),
            ),
        ]),
    ]);

    let hide_hint = if state.hide_network_info {
        " Shift+H to reveal "
    } else {
        " Shift+H to hide info "
    };
    let network_info = Paragraph::new(network_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Network Information")
            .title_bottom(
                Line::from(Span::styled(hide_hint, Style::default().fg(Color::DarkGray)))
                    .right_aligned(),
            ),
    );
    f.render_widget(network_info, info_row[0]);

    // Test Activity panel (right): renders the tail of the rolling event log
    // — same lines text mode (`--text`) prints to stderr, single source of
    // truth via `crate::event_format::format_event_lines`. Scroll with
    // ↑/↓/j/k and PgUp/PgDn while on the Dashboard tab.
    let title = if state.dashboard_log_scroll > 0 {
        format!(
            "Test Activity  (scrolled -{}, ↓ to follow)",
            state.dashboard_log_scroll
        )
    } else {
        "Test Activity  (↑↓/PgUp/PgDn to scroll)".to_string()
    };
    let hide_hint = if state.hide_network_info {
        " Shift+H to reveal "
    } else {
        " Shift+H to hide info "
    };
    let panel = Block::default()
        .borders(Borders::ALL)
        .title(title)
        .title_bottom(
            Line::from(Span::styled(hide_hint, Style::default().fg(Color::DarkGray)))
                .right_aligned(),
        );
    let inner = panel.inner(info_row[1]);
    let visible_rows = inner.height as usize;

    let activity_lines: Vec<Line> = if state.text_log.is_empty() {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No run yet — press 'r' to start",
                Style::default().fg(Color::Gray),
            )),
        ]
    } else {
        let total = state.text_log.len();
        // scroll == 0 → show newest visible_rows lines.
        // scroll == N → window ends N lines before the newest.
        let end = total.saturating_sub(state.dashboard_log_scroll);
        let start = end.saturating_sub(visible_rows);
        state.text_log[start..end]
            .iter()
            .map(|s| log_style::style_log_line(&redact_log_line(s, state)))
            .collect()
    };

    let activity = Paragraph::new(activity_lines).block(panel);
    f.render_widget(activity, info_row[1]);

    // Scrollbar on the right edge of the Test Activity panel, only when the
    // log overflows the visible area.
    let total = state.text_log.len();
    if total > visible_rows {
        let max_scroll = total.saturating_sub(visible_rows);
        // Scrollbar position is 0 at the top and `max_scroll` at the bottom.
        // Our `dashboard_log_scroll` is 0 at the bottom (newest), so flip it.
        let position = max_scroll.saturating_sub(state.dashboard_log_scroll);
        let mut scrollbar_state = ScrollbarState::new(max_scroll).position(position);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .begin_symbol(Some("↑"))
                .end_symbol(Some("↓")),
            info_row[1].inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
            &mut scrollbar_state,
        );
    }

    // Status panel (full width at bottom)
    let mut status_lines = vec![Line::from(vec![
        Span::styled("Phase: ", Style::default().fg(Color::Gray)),
        Span::raw(format!("{:?}", state.phase)),
        Span::raw("   "),
        Span::styled("Paused: ", Style::default().fg(Color::Gray)),
        Span::raw(format!("{}", state.paused)),
        Span::raw("   "),
        Span::styled("Auto-save: ", Style::default().fg(Color::Gray)),
        Span::styled(
            if state.auto_save { "ON" } else { "OFF" },
            if state.auto_save {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            },
        ),
    ])];

    // Custom comments (wrapping to fit status area)
    if let Some(comments) = state.comments.as_deref() {
        push_wrapped_status_kv(&mut status_lines, "Comments", comments, main[4].width);
    }

    // Info line - split into two lines if it contains a saved path, with wrapping
    if state.info.starts_with("Saved:") || state.info.starts_with("Saved (verifying):") {
        // Split into label and path
        if let Some(colon_pos) = state.info.find(':') {
            let (label, path) = state.info.split_at(colon_pos + 1);
            let label_text = label.trim().to_string();
            let path_str = path.trim();

            // Wrap the path to fit within available width
            // Account for borders (2 chars on each side)
            let status_area_width = main[4].width.saturating_sub(4);
            let label_width = label_text.chars().count() as u16;
            let path_chars: Vec<char> = path_str.chars().collect();
            let mut remaining = path_chars.as_slice();
            let mut is_first_path_line = true;

            while !remaining.is_empty() {
                // Calculate how many chars fit on this line
                let line_width = if is_first_path_line {
                    // First path line - account for label width
                    status_area_width.saturating_sub(label_width).max(1)
                } else {
                    // Subsequent lines - indent by 2 spaces
                    status_area_width.saturating_sub(2).max(1)
                };

                let chars_to_take = (remaining.len() as u16).min(line_width) as usize;
                let (line_chars, rest) = remaining.split_at(chars_to_take);
                let line_text: String = line_chars.iter().collect();

                if is_first_path_line {
                    // First line - include label and first part of path
                    status_lines.push(Line::from(vec![
                        Span::styled(label_text.clone(), Style::default().fg(Color::Gray)),
                        Span::raw(" "),
                        Span::raw(line_text),
                    ]));
                    is_first_path_line = false;
                } else {
                    // Subsequent lines - indent
                    status_lines.push(Line::from(vec![Span::raw("  "), Span::raw(line_text)]));
                }

                remaining = rest;
            }
        } else {
            status_lines.push(Line::from(vec![
                Span::styled("Info: ", Style::default().fg(Color::Gray)),
                Span::raw(state.info.clone()),
            ]));
        }
    } else {
        status_lines.push(Line::from(vec![
            Span::styled("Info: ", Style::default().fg(Color::Gray)),
            Span::raw(state.info.clone()),
        ]));
    }

    let status =
        Paragraph::new(status_lines).block(Block::default().borders(Borders::ALL).title("Status"));
    f.render_widget(status, main[4]);
}

pub fn draw_dashboard_compact(area: Rect, f: &mut Frame, state: &UiState) {
    // Split into top (sparklines) and bottom (text boxes)
    let content = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(8)].as_ref())
        .split(area);

    // Top row: Download and Upload sparklines side by side
    let top_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(content[0]);

    // Download sparkline with speed in title (numbers colored green)
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Line::from(vec![
                        Span::raw("Download (inst "),
                        Span::styled(
                            format!("{:.0}", state.dl_mbps),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(" / avg "),
                        Span::styled(
                            format!("{:.0}", state.dl_avg_mbps),
                            Style::default().fg(Color::Green),
                        ),
                        Span::raw(" Mbps)"),
                    ])),
            )
            .data(&state.dl_series)
            .style(Style::default().fg(Color::Green)),
        top_row[0],
    );

    // Upload sparkline with speed in title (numbers colored cyan)
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(Line::from(vec![
                        Span::raw("Upload (inst "),
                        Span::styled(
                            format!("{:.0}", state.ul_mbps),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::raw(" / avg "),
                        Span::styled(
                            format!("{:.0}", state.ul_avg_mbps),
                            Style::default().fg(Color::Cyan),
                        ),
                        Span::raw(" Mbps)"),
                    ])),
            )
            .data(&state.ul_series)
            .style(Style::default().fg(Color::Cyan)),
        top_row[1],
    );

    // Bottom row: Idle latency text box and Status box side by side
    let bottom_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(content[1]);

    // Idle latency stats text box
    let idle_lat = if state.idle_latency_samples.is_empty() && state.idle_latency_sent == 0 {
        None
    } else {
        Some(UiState::compute_live_latency_stats(
            &state.idle_latency_samples,
            state.idle_latency_sent,
            state.idle_latency_received,
        ))
    };
    let format_latency = |lat: &crate::model::LatencySummary| -> Vec<Line> {
        vec![
            Line::from(vec![
                Span::styled("avg: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:.0} ms", lat.mean_ms.unwrap_or(f64::NAN))),
            ]),
            Line::from(vec![
                Span::styled("med: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:.0} ms", lat.median_ms.unwrap_or(f64::NAN))),
            ]),
            Line::from(vec![
                Span::styled("p25: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:.0} ms", lat.p25_ms.unwrap_or(f64::NAN))),
            ]),
            Line::from(vec![
                Span::styled("p75: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:.0} ms", lat.p75_ms.unwrap_or(f64::NAN))),
            ]),
            Line::from(vec![
                Span::styled("Jitter: ", Style::default().fg(Color::Gray)),
                Span::raw(format!("{:.0} ms", lat.jitter_ms.unwrap_or(f64::NAN))),
            ]),
        ]
    };
    let idle_stats = Paragraph::new(
        idle_lat
            .as_ref()
            .map(format_latency)
            .unwrap_or_else(|| vec![Line::from("Waiting for data...")]),
    )
    .block(Block::default().borders(Borders::ALL).title("Idle Latency"));
    f.render_widget(idle_stats, bottom_row[0]);

    let mut meta_lines = vec![
        Line::from(vec![
            Span::styled("Phase: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{:?}", state.phase)),
            Span::raw("   "),
            Span::styled("Paused: ", Style::default().fg(Color::Gray)),
            Span::raw(format!("{}", state.paused)),
        ]),
        Line::from(vec![
            Span::styled("Interface: ", Style::default().fg(Color::Gray)),
            Span::raw(show_or_redact(state.interface_name.as_deref(), state.hide_network_info).to_string()),
            Span::raw(" ("),
            Span::raw(if state.is_wireless.unwrap_or(false) {
                "Wireless"
            } else {
                "Wired"
            }),
            Span::raw(")"),
        ]),
        Line::from(vec![
            Span::styled("Network: ", Style::default().fg(Color::Gray)),
            Span::raw(if state.hide_network_info {
                REDACTED_PLACEHOLDER.to_string()
            } else {
                state
                    .network_name
                    .as_deref()
                    .or_else(|| state.interface_name.as_deref())
                    .unwrap_or("-")
                    .to_string()
            }),
        ]),
    ];

    // Only show Certificate line if a certificate is set
    if let Some(ref cert_filename) = state.certificate_filename {
        meta_lines.push(Line::from(vec![
            Span::styled("Certificate: ", Style::default().fg(Color::Gray)),
            Span::raw(cert_filename),
        ]));
    }

    // Only show Proxy line if a proxy is set
    if let Some(ref proxy_url) = state.proxy_url {
        meta_lines.push(Line::from(vec![
            Span::styled("Proxy: ", Style::default().fg(Color::Gray)),
            Span::styled(proxy_url, Style::default().fg(Color::Yellow)),
        ]));
    }

    // Only show DSCP line if marking is enabled
    if let Some(ref dscp) = state.dscp_label {
        meta_lines.push(Line::from(vec![
            Span::styled("DSCP: ", Style::default().fg(Color::Gray)),
            Span::styled(dscp, Style::default().fg(Color::Yellow)),
        ]));
    }

    let hide = state.hide_network_info;
    meta_lines.extend(vec![
        Line::from(vec![
            Span::styled("IP/Colo: ", Style::default().fg(Color::Gray)),
            Span::raw(format!(
                "{} / {}",
                show_or_redact(state.ip.as_deref(), hide),
                show_or_redact(state.colo.as_deref(), hide),
            )),
        ]),
        Line::from(vec![
            Span::styled("Server: ", Style::default().fg(Color::Gray)),
            Span::raw(show_or_redact(state.server.as_deref(), hide).to_string()),
        ]),
    ]);

    // Add condensed diagnostic info if available
    let mut diag_parts: Vec<String> = Vec::new();
    if let Some(ref dns) = state.dns_summary {
        diag_parts.push(format!("DNS:{:.0}ms", dns.resolution_time_ms));
    }
    if let Some(ref tls) = state.tls_summary {
        diag_parts.push(format!("TLS:{:.0}ms", tls.handshake_time_ms));
    }
    if let Some(ref tr) = state.traceroute_summary {
        diag_parts.push(format!("Hops:{}", tr.hops.len()));
    }
    if !diag_parts.is_empty() {
        meta_lines.push(Line::from(vec![
            Span::styled("Diag: ", Style::default().fg(Color::Gray)),
            Span::raw(diag_parts.join(" | ")),
        ]));
    }
    if let Some(exp) = state
        .last_result
        .as_ref()
        .and_then(|r| r.experimental_udp.as_ref())
    {
        let label_color = quality_label_color(&exp.quality_label);
        let mos_str = exp.mos.map(|m| format!(" MOS {:.1}", m)).unwrap_or_default();
        meta_lines.push(Line::from(vec![
            Span::styled("UDP: ", Style::default().fg(Color::Gray)),
            Span::styled(&exp.quality_label, Style::default().fg(label_color)),
            Span::styled(mos_str, Style::default().fg(label_color)),
            Span::styled(format!(" loss {:.1}%", exp.latency.loss * 100.0), Style::default().fg(Color::Yellow)),
            Span::styled(format!(" reorder {:.1}%", exp.out_of_order_pct), Style::default().fg(Color::Gray)),
        ]));
        meta_lines.push(udp_split_bar(exp.latency.sent, exp.latency.received, 12));
    }

    meta_lines.extend(vec![
        Line::from(vec![
            Span::styled("Info: ", Style::default().fg(Color::Gray)),
            Span::raw(&state.info),
        ]),
        Line::from(""),
        Line::from("Keys: q quit | r rerun | p pause | s save json | tab switch | ? help"),
    ]);

    let hide_hint = if state.hide_network_info {
        " Shift+H to reveal "
    } else {
        " Shift+H to hide info "
    };
    let meta = Paragraph::new(meta_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("Network Information")
            .title_bottom(
                Line::from(Span::styled(hide_hint, Style::default().fg(Color::DarkGray)))
                    .right_aligned(),
            ),
    );
    f.render_widget(meta, bottom_row[1]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_ip_prefers_probe_result() {
        assert_eq!(
            external_ip_for_family(Some("1.2.3.4"), Some("2001:db8::1"), true),
            Some("1.2.3.4")
        );
        assert_eq!(
            external_ip_for_family(Some("2001:db8::1"), Some("1.2.3.4"), false),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn external_ip_falls_back_to_meta_ip_of_same_family() {
        assert_eq!(
            external_ip_for_family(None, Some("1.2.3.4"), true),
            Some("1.2.3.4")
        );
        assert_eq!(
            external_ip_for_family(None, Some("2001:db8::1"), false),
            Some("2001:db8::1")
        );
    }

    #[test]
    fn external_ip_ignores_meta_ip_of_other_family() {
        // --ipv6-only: the v4 probe is skipped and the meta client IP is the
        // IPv6 address; it must not appear on the IPv4 row (issue #49).
        assert_eq!(external_ip_for_family(None, Some("2001:db8::1"), true), None);
        assert_eq!(external_ip_for_family(None, Some("1.2.3.4"), false), None);
    }

    #[test]
    fn external_ip_handles_missing_or_invalid_meta_ip() {
        assert_eq!(external_ip_for_family(None, None, true), None);
        assert_eq!(external_ip_for_family(None, Some("not-an-ip"), true), None);
    }
}
