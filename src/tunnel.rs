use std::net::Ipv4Addr;
#[cfg(target_os = "linux")]
use tokio_tun::Tun;

const FAILED_INITIALIZE_TUNNEL_MESSAGE: &str = "Failed initialize tunnel device";

#[cfg(target_os = "macos")]
use tun::{Configuration, AsyncDevice};


pub struct Tunnel {}

impl Tunnel {
    #[cfg(target_os = "linux")]
    pub fn create(addr: Ipv4Addr, netmask: Ipv4Addr, mtu: i32) -> Tun {
        Tun::builder()
            .address(addr)
            .netmask(netmask)
            .destination(addr)
            .mtu(mtu)
            .tap(false)
            .packet_info(false)
            .up()
            .try_build()
            .expect(FAILED_INITIALIZE_TUNNEL_MESSAGE)
    }

    #[cfg(target_os = "macos")]
    pub fn create(addr: Ipv4Addr, netmask: Ipv4Addr, mtu: i32) -> AsyncDevice {
        let mut tunnel_config = Configuration::default();

        tunnel_config
            .address(addr)
            .netmask(netmask)
            .destination(addr)
            .mtu(mtu)
            .up();

        tun::create_as_async(&tunnel_config)
            .expect(FAILED_INITIALIZE_TUNNEL_MESSAGE)
    }
}