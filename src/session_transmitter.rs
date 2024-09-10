use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use async_std::net::UdpSocket;
use tokio::io::{AsyncWriteExt, WriteHalf};
use tokio::sync::RwLock;
use tokio_tun::Tun;
use crate::packet_decoder::PacketDecoder;
use crate::session_payload::SessionPayload;

pub struct SessionTransmitter<'a> {
    sessions_pool: &'a Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr, SocketAddr), SessionPayload>>>,
    tunnel_tx: WriteHalf<Tun>,
    udp_socket: &'a UdpSocket
}

impl<'a> SessionTransmitter<'a> {
    pub fn new(
            sessions_pool: &'a Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr, SocketAddr),
            SessionPayload>>>,
            tunnel_tx: WriteHalf<Tun>,
            udp_socket: &'a UdpSocket
    ) -> Self {
        Self {
            sessions_pool,
            tunnel_tx,
            udp_socket
        }
    }

    pub async fn poll(&mut self) {
        let mut buf = [0u8; 2048];

        while let Ok((n, sock_addr)) = self.udp_socket.recv_from(&mut buf).await {
            let sessions = self.sessions_pool.read().await;

            let Some((_, payload)) = sessions.iter()
                .find(|((_sock_addr, _, _), _)| _sock_addr == &sock_addr) else {
                log::error!("Udp Session cant finding on sessions_pool");
                continue;
            };

            let mut packet = PacketDecoder::new(&buf[..n], payload.less_safe_key());
            let frame_bytes = packet.read_string();

            self.tunnel_tx.write(&frame_bytes).await.ok();
        }
    }
}