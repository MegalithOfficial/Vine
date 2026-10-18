pub mod prefixed_stream;
pub mod proxy_protocol;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tracing::{debug, warn};

use crate::config::NetworkConfig;
pub use prefixed_stream::PrefixedRead;
pub use proxy_protocol::{IpRange, parse_proxy_protocol};

/// Creates and tunes a Tokio `TcpListener` based on `NetworkConfig`
pub fn create_tcp_listener(
    bind_addr_str: &str,
    network: &NetworkConfig,
) -> io::Result<TcpListener> {
    let addr: SocketAddr = bind_addr_str
        .parse()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let socket = if addr.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };

    socket.set_reuseaddr(true)?;

    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        let _ = socket.set_reuseport(true);
    }

    if let Some(buf) = network.recv_buffer_size {
        let _ = socket.set_recv_buffer_size(buf as u32);
    }
    if let Some(buf) = network.send_buffer_size {
        let _ = socket.set_send_buffer_size(buf as u32);
    }

    socket.bind(addr)?;
    let listener = socket.listen(network.listen_backlog)?;
    Ok(listener)
}

/// Applies socket performance options (TCP_NODELAY, KeepAlive, Buffer sizes) to a client `TcpStream`
pub fn configure_client_socket(stream: &TcpStream, config: &NetworkConfig) -> io::Result<()> {
    if let Err(e) = stream.set_nodelay(config.tcp_nodelay) {
        warn!("Failed to set TCP_NODELAY on client socket: {}", e);
    }

    let sock = socket2::SockRef::from(stream);

    if config.tcp_keepalive_secs > 0 {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(config.tcp_keepalive_secs))
            .with_interval(Duration::from_secs(10));

        if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
            debug!("Failed to set TCP keepalive on client socket: {}", e);
        }
    }

    if let Some(buf) = config.recv_buffer_size {
        let _ = sock.set_recv_buffer_size(buf);
    }
    if let Some(buf) = config.send_buffer_size {
        let _ = sock.set_send_buffer_size(buf);
    }

    Ok(())
}

/// Applies socket performance options to a backend server `TcpStream`
pub fn configure_backend_socket(stream: &TcpStream, config: &NetworkConfig) -> io::Result<()> {
    if let Err(e) = stream.set_nodelay(config.tcp_nodelay) {
        warn!("Failed to set TCP_NODELAY on backend socket: {}", e);
    }

    let sock = socket2::SockRef::from(stream);

    if config.tcp_keepalive_secs > 0 {
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(config.tcp_keepalive_secs))
            .with_interval(Duration::from_secs(10));

        if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
            debug!("Failed to set TCP keepalive on backend socket: {}", e);
        }
    }

    if let Some(buf) = config.recv_buffer_size {
        let _ = sock.set_recv_buffer_size(buf);
    }
    if let Some(buf) = config.send_buffer_size {
        let _ = sock.set_send_buffer_size(buf);
    }

    Ok(())
}
