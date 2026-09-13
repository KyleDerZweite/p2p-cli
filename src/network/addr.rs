use std::net::{IpAddr, SocketAddr};

/// Best-effort discovery of the LAN IP used for outbound traffic.
/// No packets are sent: connecting a UDP socket only selects a route.
pub fn local_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Format an IP + port as a connectable address string (brackets for IPv6).
pub fn display_addr(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}
