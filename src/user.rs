#[derive(Debug, PartialEq, Eq, Clone, sqlx::FromRow)]
pub struct User {
    pub(crate) id: u32,
    pub(crate) username: String,
    pub(crate) local_tunnel_address: u32,
    pub(crate) local_tunnel_address_str: String
}