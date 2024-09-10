mod session;
mod packet_decoder;
mod message_type;
mod packet_encoder;
mod session_context;
mod session_saturate;
mod session_claims;
mod user;
mod session_payload;
mod tunnel;
mod tunnel_transmitter;
mod session_transmitter;
mod dns;

use std::env;
use std::net::Ipv4Addr;
use std::sync::Arc;
use async_std::net::{TcpListener, UdpSocket};
use dotenv::dotenv;
use sqlx::MySqlPool;
use crate::dns::Dns;
use crate::session::Session;
use crate::session_transmitter::SessionTransmitter;
use crate::tunnel::Tunnel;
use crate::tunnel_transmitter::TunnelTransmitter;

#[tokio::main]
async fn main() {
    dotenv().ok();
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let database_url = env::var("MYSQL_DSN")
        .expect("example env error");

    let mysql_pool = MySqlPool::connect(database_url.as_str())
        .await
        .expect("Failed initialized MySQL Connection.");

    let sessions = Arc::new(Session::new(
        mysql_pool
    ));

    let tunnel = Tunnel::create(
        Ipv4Addr::new(10, 8, 0, 1),
        Ipv4Addr::new(255, 255, 0, 0),
        1450,
    );

    let (mut tunnel_rx, tunnel_tx)
        = tokio::io::split(tunnel);

    let socket = TcpListener::bind("0.0.0.0:30423")
        .await
        .expect("Socket initialization error.");


    let udp_socket = UdpSocket::bind("0.0.0.0:30423")
        .await
        .unwrap();

    let mut session_transmitter = SessionTransmitter::new(
        &sessions.sessions_pool,
        tunnel_tx,
        &udp_socket,
    );

    let mut tunnel_transmitter = TunnelTransmitter::new(
        &sessions.sessions_pool,
        &mut tunnel_rx,
        &udp_socket,
    );

    let dns_transmitter = Dns::new("0.0.0.0:5533", Vec::from("example world!"))
        .expect("Failed initialize DNS decryptor.");

    tokio::select! {
        x = async {
            while let Ok(sock) = socket.accept().await {
                let sessions_a = sessions.clone();
                let sessions_b = sessions.clone();

                tokio::task::spawn(async move {
                    let (sock_stream, sock_addr) = sock.clone();
                    sessions_a.accept((sock_stream, sock_addr)).await;

                    let session_link = {
                        let sessions = sessions_b.sessions_pool.read().await;

                        if let Some((session_link, _)) = sessions.iter().find(|((_, _, session_addr), _)| session_addr == &sock_addr) {
                            session_link.clone()
                        } else {
                            log::warn!("Session not found, skipping disconnect.");
                            return;
                        }
                    };

                    log::warn!("Session disconnected");

                    if sessions_b.sessions_pool.write().await.remove(&session_link).is_some() {
                        log::info!("success session deleted.")
                    };
                });
            }
        } => x,
        x = session_transmitter.poll() => x,
        x = tunnel_transmitter.poll() => x,
        x = dns_transmitter.expose() => x
    }
}