use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use async_std::net::UdpSocket;
use tokio::io::{AsyncReadExt, ReadHalf};
use tokio::sync::RwLock;
use tokio_tun::Tun;
use crate::packet_encoder::PacketEncoder;
use crate::session_payload::SessionPayload;

pub struct TunnelTransmitter<'a> {
    tunnel_rx: &'a mut ReadHalf<Tun>,
    udp_socket: &'a UdpSocket,
    sessions_pool: &'a Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr, SocketAddr), SessionPayload>>>,
}

impl<'a> TunnelTransmitter<'a> {
    pub fn new(
        sessions_pool: &'a Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr, SocketAddr), SessionPayload>>>,
        tunnel_rx: &'a mut ReadHalf<Tun>,
        udp_socket: &'a UdpSocket
    ) -> Self {
        Self {
            tunnel_rx,
            udp_socket,
            sessions_pool
        }
    }

    pub async fn poll(&mut self) {
        let mut buf = [0u8; 2048];


        while let Ok(n) = self.tunnel_rx.read(&mut buf).await {
            let mut packet = PacketEncoder::new();
            packet.write_string(&buf[..n]);

            if let Some(((sock_addr, _, _), payload)) = self.sessions_pool.read()
                .await
                .iter()
                .find(
                    |((_sock_addr, tunnel_addr, _), _)|
                    tunnel_addr.to_bits() == 168496130
                )
            {
                let mut packet = PacketEncoder::new();
                packet.write_string(&buf[..n]);

                let packet_bytes = packet.to_bytes(payload.less_safe_key());

                if self.udp_socket.send_to(&packet_bytes, sock_addr).await.is_err() {
                    log::error!("Failed sent to client")
                }
            }
        }
    }
}