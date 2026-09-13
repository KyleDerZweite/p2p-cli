use std::net::{IpAddr, SocketAddr};

/// Route selection only. UDP connect sends no packet.
pub fn local_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Enumerates assigned addresses using Linux iproute2, with local route fallback.
/// Diagnostics explain incomplete discovery without implying internet reachability.
pub fn local_addresses_with_diagnostics() -> (Vec<IpAddr>, Vec<String>) {
    let mut diagnostics = Vec::new();
    let mut addresses = match std::process::Command::new("ip")
        .args(["-j", "address", "show", "up"])
        .output()
    {
        Ok(output) if output.status.success() => match parse_addresses(&output.stdout) {
            Ok(addresses) => addresses,
            Err(error) => {
                diagnostics.push(format!(
                    "Could not decode local interface addresses: {error}"
                ));
                Vec::new()
            }
        },
        Ok(output) => {
            diagnostics.push(format!(
                "Local interface enumeration failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
            Vec::new()
        }
        Err(error) => {
            diagnostics.push(format!("Could not run iproute2 'ip': {error}. Only the default IPv4 route can be detected; install iproute2 to enumerate IPv6 and other interfaces."));
            Vec::new()
        }
    };
    if let Some(ip) = local_ip() {
        addresses.push(ip);
    }
    addresses.retain(|ip| {
        !ip.is_unspecified()
            && !ip.is_multicast()
            && !matches!(ip, IpAddr::V6(v6) if v6.is_unicast_link_local())
    });
    addresses.sort();
    addresses.dedup();
    if !addresses.iter().any(|ip| !ip.is_loopback()) {
        diagnostics.push("No usable non-loopback address found. Check that a network interface is up; loopback works only on this machine.".into());
    }
    diagnostics.push("Assigned addresses are candidates, not proof of reachability. Public IPv4 behind NAT must be obtained from your router and shared with --address. No public lookup or router configuration was attempted.".into());
    (addresses, diagnostics)
}

pub fn local_addresses() -> Vec<IpAddr> {
    local_addresses_with_diagnostics().0
}

fn parse_addresses(bytes: &[u8]) -> Result<Vec<IpAddr>, String> {
    let interfaces: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let interfaces = interfaces.as_array().ok_or("Expected interface array")?;
    let mut result = Vec::new();
    for interface in interfaces {
        if let Some(infos) = interface.get("addr_info").and_then(|v| v.as_array()) {
            for info in infos {
                if info.get("tentative").and_then(|v| v.as_bool()) == Some(true)
                    || info.get("dadfailed").and_then(|v| v.as_bool()) == Some(true)
                {
                    continue;
                }
                if let Some(local) = info.get("local").and_then(|v| v.as_str()) {
                    if let Ok(ip) = local.parse() {
                        result.push(ip);
                    }
                }
            }
        }
    }
    Ok(result)
}

pub fn display_addr(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

/// Only report what the operating system established; a timeout cannot identify a router policy.
pub fn connection_diagnostic(target: SocketAddr, error: &std::io::Error) -> String {
    use std::io::ErrorKind;
    let guidance = match error.kind() {
        ErrorKind::ConnectionRefused => "The destination rejected TCP. Check that p2p-cli is listening on this port and that any port forwarding targets the listener's current LAN address. A firewall can also reject TCP.",
        ErrorKind::TimedOut => "No TCP response arrived before the deadline. The peer may be offline, the address may be stale, or a firewall/NAT may silently drop traffic. This result cannot identify which router blocked it. Try reversing who connects; allow the listener's TCP port in its host firewall and router. CGNAT may require reachable IPv6 or ISP changes.",
        ErrorKind::PermissionDenied => "The local operating system denied the connection. Check local firewall policy and sandbox restrictions.",
        ErrorKind::AddrNotAvailable => "The local system cannot use this address family or source address. Check IPv6 configuration or use the peer's IPv4 candidate.",
        _ => "Check the local route, peer address, listener, and host/router firewall. For a remote private address, use a reachable public address or a network run by the two peers.",
    };
    format!(
        "TCP connect to {target}: {error} (OS code {:?}). {guidance}",
        error.raw_os_error()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_linux_addresses_and_skips_unready_addresses() {
        let data = br#"[{"addr_info":[{"local":"192.168.1.2"},{"local":"2001:db8::1"},{"local":"2001:db8::2","tentative":true}]}]"#;
        assert_eq!(
            parse_addresses(data).unwrap(),
            vec![
                "192.168.1.2".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse().unwrap()
            ]
        );
        assert!(parse_addresses(b"{}").is_err());
    }
    #[test]
    fn timeout_reports_uncertainty_and_refused_reports_evidence() {
        let target = "192.0.2.1:8080".parse().unwrap();
        assert!(
            connection_diagnostic(target, &std::io::Error::from(std::io::ErrorKind::TimedOut))
                .contains("cannot identify which router")
        );
        assert!(connection_diagnostic(
            target,
            &std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
        )
        .contains("rejected TCP"));
    }
}
