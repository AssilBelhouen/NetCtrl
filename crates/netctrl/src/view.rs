use crate::app::{App, Modal, format_rate_input};
use netctrl_core::*;
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Sparkline, Table, TableState, Wrap},
};
const CYAN: Color = Color::Rgb(71, 215, 218);
const MUTED: Color = Color::Rgb(143, 161, 181);
fn block(title: &str) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(55, 75, 96)))
}
pub fn render(f: &mut Frame, a: &App) {
    let area = f.area();
    f.render_widget(
        Block::default().style(
            Style::default()
                .bg(Color::Rgb(12, 20, 31))
                .fg(Color::Rgb(220, 231, 242)),
        ),
        area,
    );
    let layout = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(4),
        Constraint::Min(6),
        Constraint::Length(5),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(area);
    let mode = if a.sim.is_some() {
        "SIMULATION"
    } else if a.active {
        "MANAGE · IPv4"
    } else {
        "MONITOR"
    };
    let name = a
        .interface()
        .map(|i| i.name.as_str())
        .unwrap_or("no interface");
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" NETCTRL ", Style::default().fg(CYAN).bold()),
            Span::raw("/ network visibility & control"),
            Span::styled(format!("     {mode}   [{name}]"), Style::default().fg(CYAN)),
        ]))
        .block(block(" v0.1 ")),
        layout[0],
    );
    let devices = a.devices();
    let total_up: f64 = a
        .traffic
        .entries
        .values()
        .map(|t| t.current.upload_mbps())
        .sum();
    let total_down: f64 = a
        .traffic
        .entries
        .values()
        .map(|t| t.current.download_mbps())
        .sum();
    let gateway = a
        .interface()
        .and_then(|i| i.gateway)
        .map(|ip| ip.to_string())
        .unwrap_or("unresolved".into());
    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                " {} devices     ↓ {:>7.2} Mbps     ↑ {:>7.2} Mbps     Gateway {}",
                devices.len(),
                total_down,
                total_up,
                gateway
            )),
            Line::styled(
                format!(
                    " ARP {}   Capture {} packets / {} drops   {}",
                    if a.scan_running { "scanning" } else { "ready" },
                    a.capture_received,
                    a.capture_dropped,
                    if a.active {
                        "enforcement: inspect per-direction verification"
                    } else {
                        "forwarding: inactive"
                    }
                ),
                Style::default().fg(MUTED),
            ),
        ])
        .block(block(" Dashboard · observed traffic ")),
        layout[1],
    );
    if a.panel == 1 {
        let iface = a.interface();
        let text = vec![
            Line::styled(
                "Topology & capability assessment",
                Style::default().fg(CYAN).bold(),
            ),
            Line::raw(format!(
                "Interface: {}",
                iface
                    .map(|i| format!(
                        "{} · index {} · MTU {} · active {}",
                        i.name, i.index, i.mtu, i.active
                    ))
                    .unwrap_or("none".into())
            )),
            Line::raw(format!(
                "Addresses: {}",
                iface
                    .map(|i| i
                        .addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "))
                    .unwrap_or_default()
            )),
            Line::raw(format!(
                "Gateway: {gateway}; MAC must resolve before Manage can be prepared"
            )),
            Line::raw("Live path: selected IPv4 clients → controller → selected gateway"),
            Line::raw(
                "Forwarding available only after topology, privilege and firewall validation",
            ),
            Line::raw(
                "Other switched clients' traffic may be unobservable. Isolation is only suspected.",
            ),
            Line::styled(
                "IPv6 can bypass IPv4 limits. Same-subnet traffic is outside shaping.",
                Style::default().fg(Color::Yellow),
            ),
            Line::raw("I: choose interface · M: preview/stop Manage · X: recovery"),
        ];
        f.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .block(block(" Topology ")),
            layout[2],
        );
    } else if a.panel == 2 {
        let mut lines = vec![
            Line::styled("Enforcement and recovery", Style::default().fg(CYAN).bold()),
            Line::raw("AppliedUnverified: backend confirmed objects; no traffic proof yet."),
            Line::raw("TrafficVerified: packets traversed the allowed forwarding path."),
            Line::raw("Capture bytes, shaped bytes and forwarded bytes have different meanings."),
        ];
        for (ip, c) in &a.enforcement {
            lines.push(Line::raw(format!(
                "{ip} ↑ {:?} {} B / ↓ {:?} {} B / {} drops",
                c.upload, c.uploaded, c.download, c.downloaded, c.dropped
            )));
        }
        lines.push(Line::styled(
            "Q restores owned state. X requests recovery. CLI: netctrl recover",
            Style::default().fg(CYAN),
        ));
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .block(block(" Recovery & counters ")),
            layout[2],
        );
    } else {
        let rows = devices.iter().map(|d| {
            let t = a.traffic.entries.get(&d.id);
            let observed = t.is_some_and(|t| t.observable);
            let p = a.policy(d.id);
            let ip = d
                .addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let status = if let Some(c) = d.addresses.first().and_then(|ip| a.enforcement.get(ip)) {
                format!("↑{} ↓{}", short(&c.upload), short(&c.download))
            } else {
                format!("{:?}", d.presence)
            };
            Row::new(vec![
                Cell::from(ip),
                Cell::from(d.id.mac.to_string()),
                Cell::from(sanitize(d.hostname.as_deref().unwrap_or("—"))),
                Cell::from(if observed {
                    format!(
                        "{:.2} M",
                        t.map(|t| t.current.download_mbps()).unwrap_or(0.0)
                    )
                } else {
                    "unseen".into()
                }),
                Cell::from(if observed {
                    format!("{:.2} M", t.map(|t| t.current.upload_mbps()).unwrap_or(0.0))
                } else {
                    "unseen".into()
                }),
                Cell::from(format_rate_input(p.download_bps)),
                Cell::from(format_rate_input(p.upload_bps)),
                Cell::from(format!(
                    "{status}{}",
                    if d.ipv6_seen { " · v6" } else { "" }
                )),
            ])
            .style(Style::default().fg(if d.presence == Presence::Conflict {
                Color::Red
            } else {
                Color::Rgb(215, 225, 235)
            }))
        });
        let table = Table::new(
            rows,
            [
                Constraint::Length(15),
                Constraint::Length(17),
                Constraint::Min(12),
                Constraint::Length(10),
                Constraint::Length(10),
                Constraint::Length(9),
                Constraint::Length(9),
                Constraint::Length(18),
            ],
        )
        .header(
            Row::new([
                "IP Address",
                "MAC Address",
                "Hostname",
                "Download",
                "Upload",
                "↓ Limit M",
                "↑ Limit M",
                "Status",
            ])
            .style(Style::default().fg(CYAN).bold()),
        )
        .block(block(" Devices · limits in Mbps · u = unlimited "))
        .row_highlight_style(Style::default().bg(Color::Rgb(25, 61, 76)).bold())
        .highlight_symbol("› ");
        let mut state = TableState::default().with_selected(Some(a.selected));
        f.render_stateful_widget(table, layout[2], &mut state);
    }
    let history: Vec<u64> = a
        .selected_device()
        .and_then(|d| a.traffic.entries.get(&d.id))
        .map(|t| {
            t.history
                .iter()
                .map(|s| (s.download_bps / 1000.0) as u64)
                .collect()
        })
        .unwrap_or_default();
    f.render_widget(
        Sparkline::default()
            .block(block(
                " Selected device · download history (observed kbps) ",
            ))
            .data(&history)
            .style(Style::default().fg(CYAN)),
        layout[3],
    );
    f.render_widget(
        Paragraph::new(sanitize(&a.message))
            .wrap(Wrap { trim: false })
            .block(block(" Status ")),
        layout[4],
    );
    let footer = if a.active || a.devices().iter().any(|d| d.ipv6_seen) {
        " IPv6 BYPASSES LIMITS · ↑↓ select · Enter details · S scan · L limits · M mode · Tab panels · H help · Q quit "
    } else {
        " ↑↓ select · Enter details · S scan · L limits · M mode · R sample · Tab panels · I interface · H help · Q quit "
    };
    f.render_widget(
        Paragraph::new(footer).style(Style::default().fg(MUTED)),
        layout[5],
    );
    if !matches!(a.modal, Modal::None) {
        modal(f, a);
    }
}
fn short(s: &EnforcementStatus) -> &str {
    match s {
        EnforcementStatus::TrafficVerified => "verified",
        EnforcementStatus::AppliedUnverified => "pending",
        EnforcementStatus::Desired => "desired",
        EnforcementStatus::Failed(_) => "failed",
        EnforcementStatus::Inactive => "off",
    }
}
fn modal(f: &mut Frame, a: &App) {
    let area = f.area();
    let width = area.width.saturating_sub(4).min(100);
    let height = area.height.saturating_sub(4).min(25);
    let rect = Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    );
    let (title, lines): (String, Vec<Line<'static>>) = match &a.modal {
        Modal::Help => (
            " Keyboard help ".into(),
            [
                "↑ / ↓ navigate · Enter device details",
                "S bounded scan; enables automatic periodic active discovery after consent",
                "L edit desired upload/download Mbps; Tab switches fields; u = unlimited",
                "M prepare Manage / stop and restore · Y confirms a concrete plan",
                "R sample statistics · Tab dashboard/topology/recovery panels",
                "I choose interface · X recovery · Q quit and restore owned changes",
                "Visible traffic is not total device traffic. IPv6 can bypass IPv4 limits.",
                "Press any key to close",
            ]
            .into_iter()
            .map(Line::raw)
            .collect(),
        ),
        Modal::EnableScan => (
            " Enable active discovery? ".into(),
            vec![
                Line::raw(format!(
                    "Send ARP probes only inside the selected local subnet, cap {} addresses at {} probes/sec.",
                    a.config.max_scan_hosts, a.config.scan_probes_per_sec
                )),
                Line::raw(format!(
                    "Continue periodically every {} seconds after scans complete.",
                    a.config.scan_interval_secs
                )),
                Line::styled("Y enable and scan · N cancel", Style::default().fg(CYAN)),
            ],
        ),
        Modal::Interfaces { cursor } => (
            " Choose interface · ↑↓ / Enter / Esc ".into(),
            a.interfaces
                .iter()
                .enumerate()
                .map(|(n, i)| {
                    Line::raw(format!(
                        "{} {}  {}  {}  gateway {:?}",
                        if n == *cursor { "›" } else { " " },
                        i.name,
                        if i.active { "UP" } else { "DOWN" },
                        i.addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(","),
                        i.gateway
                    ))
                })
                .collect(),
        ),
        Modal::Details => {
            let d = a.selected_device();
            let lines = if let Some(d) = d {
                let traffic = a.traffic.entries.get(&d.id);
                vec![
                    Line::raw(format!(
                        "IP {:?} · MAC {} · {:?}",
                        d.addresses, d.id.mac, d.presence
                    )),
                    Line::raw(format!(
                        "Hostname {} · IPv6 observed {}",
                        d.hostname.as_deref().unwrap_or("unresolved"),
                        d.ipv6_seen
                    )),
                    Line::raw(format!(
                        "Upload {} B · Download {} B · {} packets",
                        traffic.map(|t| t.uploaded).unwrap_or(0),
                        traffic.map(|t| t.downloaded).unwrap_or(0),
                        traffic.map(|t| t.packets).unwrap_or(0)
                    )),
                    Line::raw(format!(
                        "Observed download {:.2} KB/s (decimal)",
                        traffic.map(|t| t.current.download_kb_s()).unwrap_or(0.0)
                    )),
                    Line::styled(
                        "IPv4 enforcement does not constrain IPv6 or direct LAN traffic.",
                        Style::default().fg(Color::Yellow),
                    ),
                    Line::raw("Press any key to close"),
                ]
            } else {
                vec![Line::raw("No device selected")]
            };
            (" Device details ".into(), lines)
        }
        Modal::Limits {
            field, up, down, ..
        } => (
            " Desired limits · Mbps ".into(),
            vec![
                Line::raw(format!("{} Upload: {up}", if !field { "›" } else { " " })),
                Line::raw(format!(
                    "{} Download: {down}",
                    if *field { "›" } else { " " }
                )),
                Line::raw("Backspace to edit · u = unlimited · Tab switch field"),
                Line::styled(
                    "Enter saves/prepares replacement · Esc cancels",
                    Style::default().fg(CYAN),
                ),
                Line::raw("Changes require a separate confirmation before network application."),
            ],
        ),
        Modal::Confirm { plan, changes, .. } => {
            let mut l = changes
                .iter()
                .map(|s| Line::raw(sanitize(s)))
                .collect::<Vec<_>>();
            for t in &plan.targets {
                l.push(Line::raw(format!(
                    "{} [{}] upload {} Mbps; download {} Mbps",
                    t.peer.ip,
                    t.peer.mac,
                    format_rate_input(t.policy.upload_bps),
                    format_rate_input(t.policy.download_bps)
                )));
            }
            l.push(Line::styled(
                "Authorized local network only. IPv6 may bypass. Exit triggers recovery.",
                Style::default().fg(Color::Yellow),
            ));
            l.push(Line::styled(
                "Y apply these changes · N cancel (preview expires after 60 seconds)",
                Style::default().fg(CYAN).bold(),
            ));
            (" Confirm network changes ".into(), l)
        }
        Modal::None => return,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(block(&title).style(Style::default().bg(Color::Rgb(20, 34, 49)))),
        rect,
    );
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dashboard_and_confirmation() -> Result<()> {
        let a = App::new(Config::default(), "unused".into(), vec![], true)?;
        let backend = ratatui::backend::TestBackend::new(130, 35);
        let mut t = Terminal::new(backend)?;
        t.draw(|f| render(f, &a))?;
        let s = t
            .backend()
            .buffer()
            .content
            .iter()
            .map(|c| c.symbol())
            .collect::<String>();
        assert!(s.contains("SIMULATION"));
        assert!(s.contains("IP Address"));
        Ok(())
    }
}
