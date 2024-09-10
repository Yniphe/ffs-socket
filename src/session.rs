use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use async_std::future;
use async_std::io::ReadExt;
use async_std::net::{TcpStream};
use futures::AsyncWriteExt;
use jsonwebtoken::{DecodingKey};
use ring::aead::{LessSafeKey, UnboundKey};
use ring::agreement;
use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey};
use ring::rand::SystemRandom;
use sqlx::{MySql, Pool};
use tokio::sync::RwLock;

use crate::message_type::MessageType;
use crate::packet_decoder::PacketDecoder;
use crate::packet_encoder::PacketEncoder;
use crate::session_claims::SessionClaims;
use crate::session_context::SessionContext;
use crate::session_payload::SessionPayload;
use crate::session_saturate::SessionSaturate;
use crate::user::User;

pub struct Session {
    pub mysql_pool: Pool<MySql>,
    pub jwk: DecodingKey,
    pub sessions_pool: Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr, SocketAddr), SessionPayload>>>
}

impl Session {
    pub fn new(mysql_pool: Pool<MySql>) -> Self {
        let jwt_shared_secret = std::env::var("JWT_SHARED_SECRET")
            .expect("Failed import JWT_SHARED_SECRET.");

        let jwk = DecodingKey::from_secret(
            &jwt_shared_secret.as_ref()
        );

        let sessions_pool = Arc::new(
            RwLock::new(HashMap::new())
        );

        Self {
            mysql_pool,
            jwk,
            sessions_pool
        }
    }

    pub async fn accept(self: Arc<Self>, (mut socket_stream, socket_address): (TcpStream, SocketAddr)) {
        let mut buf = [0u8; 2048];
        let mut context = SessionContext::new();

        loop {
            let handle = future::timeout(
                Duration::from_secs(10),
                ReadExt::read(&mut socket_stream, &mut buf),
            ).await;

            match handle {
                Ok(Ok(0)) => {
                    println!("socket disconnect");
                    break;
                }
                Ok(Ok(n)) => {
                    let pk = context.pk();
                    let mut packet = PacketDecoder::new(&buf[..n], pk);
                    let opcode = packet.read_opcode();

                    match opcode {
                        MessageType::Sign if context.saturate == SessionSaturate::Init => {
                            let remote_client_pk = packet.read_string();

                            let Ok(key_pair) = EphemeralPrivateKey::generate(
                                &agreement::X25519,
                                &SystemRandom::new(),
                            ) else {
                                log::error!("failed generate private key");
                                return;
                            };

                            // example log
                            let Ok(local_context_pk) = key_pair.compute_public_key() else {
                                log::error!("Failed compuse session public_key.");
                                return;
                            };

                            // Используем borrow для получения изменяемой ссылки на key_pair
                            let Ok(ctx_shared_key) = agreement::agree_ephemeral(
                                key_pair,
                                &UnparsedPublicKey::new(&agreement::X25519, remote_client_pk),
                                |material| material.to_vec()) else {
                                log::error!("Failed create shared_key for session");
                                break;
                            };

                            let Ok(ctx_unbound_key) = UnboundKey::new(
                                &ring::aead::AES_256_GCM, &ctx_shared_key) else {
                                log::error!("Failed create unbound_context_key.");
                                break;
                            };

                            let ctx_less_safe_key = LessSafeKey::new(ctx_unbound_key);

                            // клонируем ключ в сессию.
                            context.set_pk(
                                ctx_less_safe_key.clone()
                            );

                            // Обозначаем статус сесси.
                            context.saturate(SessionSaturate::WaitApprove);

                            let mut packet = PacketEncoder::new();

                            packet.write_opcode(MessageType::SignWaitApprove);
                            packet.write_string(
                                local_context_pk.as_ref()
                            );

                            let packet_bytes = packet.to_bytes(None);

                            if socket_stream.write(&packet_bytes).await.is_err() {
                                log::error!("Failed sent packet to session, abort.");
                                break;
                            }
                        }
                        MessageType::SignApprove if context.saturate == SessionSaturate::WaitApprove => {
                            let Ok(access_token) = String::from_utf8(packet.read_string()) else {
                                log::error!("failed convert access_token to str");
                                break;
                            };

                            let Ok(token_data_payload) = jsonwebtoken::decode::<SessionClaims>(&access_token, &self.jwk, &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS512)) else {
                                log::error!("failed decode session token payload");
                                break;
                            };

                            let Ok(payload) = sqlx::query_as::<_, User>("SELECT id, username, local_tunnel_address, INET_NTOA(local_tunnel_address) as local_tunnel_address_str FROM users WHERE id = ? and enabled = 1")
                                .bind(token_data_payload.claims.identifier)
                                .fetch_one(&self.mysql_pool).await else {
                                break;
                            };

                            if let Some(_) = self.sessions_pool.read()
                                .await
                                .iter()
                                .find(
                                    |((_sock_addr, tunnel_addr, _), _)|
                                    tunnel_addr.to_bits() == payload.local_tunnel_address
                                )
                            {
                                log::warn!("Session exists remove context;");
                                break;
                            }

                            let ctx_sock_port = packet.read_uint16();
                            let mut packet = PacketEncoder::new();

                            packet.write_opcode(MessageType::SignApprove);
                            packet.write_string("Привет, Мир!".as_ref());

                            socket_stream.write(&packet.to_bytes(context.pk())).await.ok();
                            context.saturate(SessionSaturate::Success);

                            let clone_session_pk = context.pk().clone();
                            let session_payload = SessionPayload::new(
                                payload.clone(),
                                clone_session_pk
                            );

                            let session_link = (
                                SocketAddr::new(socket_address.ip(), ctx_sock_port),
                                Ipv4Addr::from(payload.local_tunnel_address),
                                socket_address
                            );

                            let mut sessions = self.sessions_pool.write().await;
                            sessions.insert(session_link, session_payload);
                        },
                        MessageType::Trace if context.saturate == SessionSaturate::Success => { },
                        _ => {
                            log::info!("unsigned message. client has disconnected. {:?}", opcode);
                            break;
                        }
                    }
                }
                // tcp socket timeout error
                Err(err) => {
                    println!("Client timed out {err}");
                    break;
                }
                _ => {
                    println!("this code worked");
                    break;
                }
            }
        }
    }

    // pub async fn example(&self, x: &Arc<RwLock<HashMap<(SocketAddr, Ipv4Addr), SessionPayload>>>, mut tunnel_tx: tokio::io::WriteHalf<Tun>) {

}