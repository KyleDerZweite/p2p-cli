use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Best-effort discovery of the LAN IP used for outbound traffic.
/// No packets are sent: connecting a UDP socket only selects a route.
pub fn local_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip())
}

/// Best-effort public IP lookup via api.ipify.org over plain HTTP.
/// Only our own public IP is revealed to the service, which any outbound
/// connection reveals anyway; no identity material leaves the machine.
pub async fn fetch_public_ip() -> Option<IpAddr> {
    let result = timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(("api.ipify.org", 80)).await.ok()?;
        stream
            .write_all(
                b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n",
            )
            .await
            .ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        let response = String::from_utf8(response).ok()?;
        let body = response.split("\r\n\r\n").nth(1)?;
        body.trim().parse::<IpAddr>().ok()
    })
    .await;
    result.ok().flatten()
}

/// Format an IP + port as a connectable address string (brackets for IPv6).
pub fn display_addr(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}
