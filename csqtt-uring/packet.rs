// SPDX-FileCopyrightText: 2026 amurcanov
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const PACKET_CAPACITY: usize = 1600;
pub const UDP_RX_SLOTS: usize = 64;
pub const UDP_TX_SLOTS: usize = 512;
pub const TUN_TX_SLOTS: usize = 512;
pub const COMPLETION_BATCH: usize = 256;
pub const TUN_MTU: u16 = 1300;

pub struct PacketBuffer {
    bytes: Box<[u8; PACKET_CAPACITY]>,
    len: usize,
}

impl PacketBuffer {
    pub fn new() -> Self {
        Self {
            bytes: Box::new([0; PACKET_CAPACITY]),
            len: 0,
        }
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        PACKET_CAPACITY
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }

    #[inline(always)]
    pub fn storage_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..]
    }

    #[inline(always)]
    pub fn set_len(&mut self, len: usize) -> bool {
        if len > PACKET_CAPACITY {
            return false;
        }
        self.len = len;
        true
    }

    #[inline(always)]
    pub fn copy_from(&mut self, data: &[u8]) -> bool {
        if data.len() > PACKET_CAPACITY {
            return false;
        }
        self.bytes[..data.len()].copy_from_slice(data);
        self.len = data.len();
        true
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[inline(always)]
pub fn extract_dst_ipv4(packet: &[u8]) -> Option<[u8; 4]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    Some([packet[16], packet[17], packet[18], packet[19]])
}

pub fn socket_addr_to_storage(
    address: SocketAddr,
    storage: &mut libc::sockaddr_storage,
) -> libc::socklen_t {
    unsafe {
        std::ptr::write_bytes(
            storage as *mut libc::sockaddr_storage as *mut u8,
            0,
            std::mem::size_of::<libc::sockaddr_storage>(),
        );
    }
    match address {
        SocketAddr::V4(address) => {
            let raw = storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in;
            unsafe {
                (*raw).sin_family = libc::AF_INET as libc::sa_family_t;
                (*raw).sin_port = address.port().to_be();
                (*raw).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(address.ip().octets()),
                };
            }
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(address) => {
            let raw = storage as *mut libc::sockaddr_storage as *mut libc::sockaddr_in6;
            unsafe {
                (*raw).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*raw).sin6_port = address.port().to_be();
                (*raw).sin6_flowinfo = address.flowinfo();
                (*raw).sin6_addr = libc::in6_addr {
                    s6_addr: address.ip().octets(),
                };
                (*raw).sin6_scope_id = address.scope_id();
            }
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

pub fn storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as i32 {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let raw =
                unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(raw.sin_addr.s_addr.to_ne_bytes());
            Some(SocketAddr::new(IpAddr::V4(ip), u16::from_be(raw.sin_port)))
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let raw = unsafe {
                &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6)
            };
            let ip = Ipv6Addr::from(raw.sin6_addr.s6_addr);
            Some(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                u16::from_be(raw.sin6_port),
                raw.sin6_flowinfo,
                raw.sin6_scope_id,
            )))
        }
        _ => None,
    }
}
