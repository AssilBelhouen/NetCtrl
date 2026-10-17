use futures_util::TryStreamExt;
use netctrl_core::*;
use netlink_packet_route::{
    AddressFamily,
    address::AddressAttribute,
    link::{LinkAttribute, LinkFlags},
    neighbour::{NeighbourAttribute, NeighbourState},
    route::RouteAttribute,
};
use rtnetlink::RouteMessageBuilder;
use std::net::{IpAddr, Ipv4Addr};
fn error(e: impl std::fmt::Display) -> Error {
    Error::Backend(format!("netlink: {e}"))
}
fn connection() -> Result<rtnetlink::Handle> {
    let (c, h, _) = rtnetlink::new_connection().map_err(error)?;
    tokio::spawn(c);
    Ok(h)
}
pub async fn interfaces() -> Result<Vec<Interface>> {
    let h = connection()?;
    let mut out = vec![];
    let mut links = h.link().get().execute();
    while let Some(l) = links.try_next().await.map_err(error)? {
        let mut i = Interface {
            index: l.header.index,
            name: String::new(),
            active: l.header.flags.contains(LinkFlags::Up)
                && l.header.flags.contains(LinkFlags::LowerUp),
            ethernet: false,
            mac: None,
            addresses: vec![],
            gateway: None,
            mtu: 1500,
        };
        for a in l.attributes {
            match a {
                LinkAttribute::IfName(n) => i.name = n,
                LinkAttribute::Address(a) if a.len() == 6 => {
                    let mut m = [0; 6];
                    m.copy_from_slice(&a);
                    i.mac = Some(Mac(m));
                    i.ethernet = Mac(m).is_unicast();
                }
                LinkAttribute::Mtu(m) => i.mtu = m,
                _ => {}
            }
        }
        out.push(i);
    }
    let mut addresses = h.address().get().execute();
    while let Some(a) = addresses.try_next().await.map_err(error)? {
        if a.header.family != AddressFamily::Inet {
            continue;
        }
        for attr in a.attributes {
            if let AddressAttribute::Local(IpAddr::V4(ip)) = attr
                && let Some(i) = out.iter_mut().find(|i| i.index == a.header.index)
            {
                i.addresses.push(
                    netctrl_core::config_subnet::Ipv4Net::new(ip, a.header.prefix_len)
                        .map_err(error)?,
                );
            }
        }
    }
    let route = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = h.route().get(route).execute();
    let mut candidates = std::collections::BTreeMap::<u32, (u32, Ipv4Addr)>::new();
    while let Some(r) = routes.try_next().await.map_err(error)? {
        if r.header.destination_prefix_length != 0 || r.header.table != 254 {
            continue;
        }
        let (mut idx, mut gw, mut metric) = (None, None, 0);
        for a in r.attributes {
            match a {
                RouteAttribute::Oif(n) => idx = Some(n),
                RouteAttribute::Gateway(netlink_packet_route::route::RouteAddress::Inet(ip)) => {
                    gw = Some(ip)
                }
                RouteAttribute::Priority(m) => metric = m,
                _ => {}
            }
        }
        if let (Some(idx), Some(gw)) = (idx, gw)
            && candidates.get(&idx).is_none_or(|(m, _)| metric < *m)
        {
            candidates.insert(idx, (metric, gw));
        }
    }
    for i in &mut out {
        i.gateway = candidates.get(&i.index).map(|(_, g)| *g);
    }
    Ok(out)
}
pub async fn neighbors(index: u32) -> Result<Vec<Peer>> {
    let h = connection()?;
    let mut ns = h
        .neighbours()
        .get()
        .set_family(rtnetlink::IpVersion::V4)
        .execute();
    let mut out = vec![];
    while let Some(n) = ns.try_next().await.map_err(error)? {
        if n.header.ifindex != index {
            continue;
        }
        if matches!(
            n.header.state,
            NeighbourState::Failed | NeighbourState::Incomplete | NeighbourState::None
        ) {
            continue;
        }
        let (mut ip, mut mac) = (None, None);
        for a in n.attributes {
            match a {
                NeighbourAttribute::Destination(
                    netlink_packet_route::neighbour::NeighbourAddress::Inet(a),
                ) => ip = Some(a),
                NeighbourAttribute::LinkLocalAddress(a) if a.len() == 6 => {
                    let mut m = [0; 6];
                    m.copy_from_slice(&a);
                    mac = Some(Mac(m));
                }
                _ => {}
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac)
            && mac.is_unicast()
        {
            out.push(Peer { ip, mac });
        }
    }
    Ok(out)
}
pub async fn revalidate(plan: &SessionPlan) -> Result<()> {
    plan.validate()?;
    let actual = interfaces()
        .await?
        .into_iter()
        .find(|i| i.index == plan.interface.index)
        .ok_or_else(|| Error::Conflict("interface disappeared".into()))?;
    if actual != plan.interface {
        return Err(Error::Conflict(
            "interface addresses, MAC, route, MTU or link state changed; prepare again".into(),
        ));
    }
    let ns = neighbors(actual.index).await?;
    for p in std::iter::once(&plan.gateway).chain(plan.targets.iter().map(|t| &t.peer)) {
        if !ns.iter().any(|n| n == p) {
            return Err(Error::Conflict(format!(
                "{} neighbor mapping is missing or changed",
                p.ip
            )));
        }
    }
    // Reject alternate policy routes and VPNs rather than forwarding via an unintended interface.
    let h = connection()?;
    let r = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix("1.1.1.1".parse().map_err(error)?, 32)
        .build();
    let mut routes = h.route().get(r).execute();
    let mut valid = false;
    while let Some(route) = routes.try_next().await.map_err(error)? {
        if route
            .attributes
            .iter()
            .any(|a| matches!(a,RouteAttribute::Oif(i) if *i==actual.index))
        {
            valid = true;
        }
    }
    if !valid {
        return Err(Error::Unsupported(
            "default traffic does not use the selected interface".into(),
        ));
    }
    Ok(())
}
