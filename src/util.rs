use std::collections::HashSet;
use std::io::Error;
use std::mem;
use std::os::fd::RawFd;

use libc::c_int;
use libc::{c_uchar, ioctl, sockaddr_ll, socket, ETH_ALEN, SIOCGIFINDEX};
use libc::{ifreq, AF_PACKET, ETH_P_ALL, SOCK_RAW};

use rand::Rng;
use std::ffi::CString;

pub fn select_private_ip(count: usize, classify: u8, rng: &mut impl Rng) -> Vec<String> {
    let mut ips = HashSet::new();
    match classify {
        0 => {
            while ips.len() < count {
                let second_octet = rng.gen_range(0..=255);
                let third_octet = rng.gen_range(0..=255);
                let fourth_octet = rng.gen_range(1..=254);
                let ip = format!("10.{}.{}.{}", second_octet, third_octet, fourth_octet);
                ips.insert(ip);
            }
        }
        1 => {
            while ips.len() < count {
                let second_octet = rng.gen_range(16..=31);
                let third_octet = rng.gen_range(0..=255);
                let fourth_octet = rng.gen_range(1..=254);
                let ip = format!("172.{}.{}.{}", second_octet, third_octet, fourth_octet);
                ips.insert(ip);
            }
        }
        2 => {
            while ips.len() < count {
                let third_octet = rng.gen_range(0..=255);
                let fourth_octet = rng.gen_range(1..=254);
                let ip = format!("192.168.{}.{}", third_octet, fourth_octet);
                ips.insert(ip);
            }
        }
        _ => {}
    }
    ips.into_iter().map(|k| k).collect()
}

pub fn create_raw_socket() -> Result<RawFd, Error> {
    unsafe {
        let sockfd = socket(AF_PACKET, SOCK_RAW, ETH_P_ALL.to_be());
        if sockfd < 0 {
            return Err(Error::last_os_error());
        }
        Ok(sockfd)
    }
}

pub fn bind_to_interface(
    sockfd: c_int,
    ifname: &str,
    socket_addr: &mut sockaddr_ll,
) -> Result<(), Error> {
    unsafe {
        let ifname_cstr = CString::new(ifname).unwrap();
        let mut ifreq: ifreq = mem::zeroed();
        std::ptr::copy_nonoverlapping(
            ifname_cstr.as_ptr(),
            ifreq.ifr_name.as_mut_ptr(),
            ifname.len(),
        );

        if ioctl(sockfd, SIOCGIFINDEX, &ifreq as *const ifreq as *const _) < 0 {
            return Err(Error::last_os_error());
        }
        socket_addr.sll_ifindex = ifreq.ifr_ifru.ifru_ifindex;
        socket_addr.sll_halen = ETH_ALEN as c_uchar;
    }
    Ok(())
}
