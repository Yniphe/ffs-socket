use crate::packet_decoder::PacketDecoder;
use crate::packet_encoder::PacketEncoder;

pub struct Dns {
    pub async_socket: tokio::net::UdpSocket,
    pub shared: Vec<u8>,
}

impl Dns {
    pub fn new(addr: &str, shared: Vec<u8>) -> std::io::Result<Self> {
        let socket = std::net::UdpSocket::bind(addr)?;
        log::info!("Success initialize UDP Socket for crypt DNS");

        socket.set_nonblocking(true)?;

        let async_socket = tokio::net::UdpSocket::from_std(socket)?;

        Ok(Self {
            async_socket,
            shared,
        })
    }

    pub async fn expose(&self) {
        let mut buf = [0u8; 2048];
        while let Ok((n, sock_addr)) = self.async_socket.recv_from(&mut buf).await {
            let mut packet = PacketDecoder::new_xor(&buf[..n], self.shared.clone());
            let bytes = packet.read_string();
            let shared = self.shared.clone();

            tokio::task::spawn(async move {
                let mut buf = [0u8; 2048];
                let Ok(socket) = tokio::net::UdpSocket::bind("0.0.0.0:0").await else {
                    log::error!("failed bind dns-client socket.");
                    return;
                };

                if let Ok(n) = socket.send_to(&bytes, "1.1.1.1:53").await {
                    log::info!("success sent to dns server.")
                }

                if let Ok(n) = socket.recv(&mut buf).await {

                    let bytes = &buf[..n];
                    let mut packet = PacketEncoder::new();

                    packet.write_string(bytes);

                    if let Ok(n) = socket.send_to(&packet.to_bytes_with_xor(shared), sock_addr).await {
                        log::info!("Success sent dns info to another socket.")
                    }
                }
            });
        }
    }
}