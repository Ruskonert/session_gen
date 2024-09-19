use serde::{de::Error, Deserialize};
use std::{fs::File, io::Read, net::IpAddr, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum GenConfigProtocol {
    Raw,
    Tcp,
    Udp,
    Icmp,

    // preset
    Http,

    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenConfigPayload {
    pub rev: bool,
    pub payload: Option<Vec<u8>>,
    pub flags: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GenConfig {
    pub l2_smac: [u8; 6],
    pub l2_dmac: [u8; 6],
    pub l3_saddr: [u8; 16],
    pub l3_daddr: [u8; 16],
    pub is_ipv6: bool,
    pub proto: GenConfigProtocol,
    pub l4_sport: u16,
    pub l4_dport: u16,
    pub payloads: Vec<GenConfigPayload>,
}

impl GenConfig {
    pub fn from_path(cfg_path: &str) -> Result<Self, toml::de::Error> {
        if let Some(s) = GenUndefConfig::from_file(cfg_path) {
            Self::from_config(&s)
        } else {
            Err(toml::de::Error::custom(
                "Not vaild path, should be vaild path.",
            ))
        }
    }

    pub(crate) fn from_config(cfg: &GenUndefConfig) -> Result<Self, toml::de::Error> {
        let mut gc: GenConfig = GenConfig {
            l2_smac: [0 as u8; 6],
            l2_dmac: [0 as u8; 6],
            l3_saddr: [0 as u8; 16],
            l3_daddr: [0 as u8; 16],
            is_ipv6: false,
            proto: GenConfigProtocol::Raw,
            l4_sport: 10000,
            l4_dport: 80,
            payloads: vec![],
        };

        let conv_mac = |s: &str| {
            let spliter: Vec<&str> = s.split(":").into_iter().map(|ss| ss).collect();
            let mut vecs = [0 as u8; 6];
            if spliter.len() != 6 {
                return None;
            }

            for (i, sp) in spliter.into_iter().enumerate() {
                match u8::from_str_radix(sp, 16) {
                    Ok(n) => {
                        vecs[i] = n;
                    }
                    Err(e) => {
                        eprintln!("{:?}", e);
                        return None;
                    }
                }
            }
            Some(vecs)
        };

        let conv_ip = |s: &str| {
            match IpAddr::from_str(s) {
                Ok(ip_addr) => {
                    // IpAddr을 Ipv4Addr로 변환
                    if let IpAddr::V4(ipv4_addr) = ip_addr {
                        Some((true, ipv4_addr.octets().to_vec()))
                    } else {
                        if let IpAddr::V6(ipv6_addr) = ip_addr {
                            Some((false, ipv6_addr.octets().to_vec()))
                        } else {
                            None
                        }
                    }
                }
                Err(e) => {
                    eprintln!("{:?}", e);
                    return None;
                }
            }
        };

        if let Some(l2_smac) = &cfg.l2_smac {
            if let Some(l2_smac) = conv_mac(&l2_smac) {
                gc.l2_smac[..6].copy_from_slice(&l2_smac);
            }
        }

        if let Some(l2_dmac) = &cfg.l2_dmac {
            if let Some(l2_dmac) = conv_mac(&l2_dmac) {
                gc.l2_dmac[..6].copy_from_slice(&l2_dmac);
            }
        }

        let mut src_ipv6 = false;
        let mut dst_ipv6 = false;
        if let Some(l3_saddr) = &cfg.l3_saddr {
            if let Some((is_ipv4, l3_saddr)) = conv_ip(&l3_saddr) {
                if is_ipv4 {
                    gc.l3_saddr[..4].copy_from_slice(&l3_saddr);
                } else {
                    gc.l3_saddr[..16].copy_from_slice(&l3_saddr);
                    src_ipv6 = true;
                }
            }
        }

        if let Some(l3_daddr) = &cfg.l3_daddr {
            if let Some((is_ipv4, l3_daddr)) = conv_ip(&l3_daddr) {
                if is_ipv4 {
                    gc.l3_daddr[..4].copy_from_slice(&l3_daddr);
                } else {
                    gc.l3_daddr[..16].copy_from_slice(&l3_daddr);
                    dst_ipv6 = true;
                }
            }
        }

        if src_ipv6 != dst_ipv6 {
            return Err(toml::de::Error::custom(format!(
                "Invaild IP version pair, src_ipv6={}, dst_ipv6={}",
                src_ipv6, dst_ipv6
            )));
        }
        gc.is_ipv6 = src_ipv6;

        if let Some(l3_proto) = &cfg.l3_proto {
            let proto = match l3_proto.to_uppercase().as_str() {
                "TCP" => GenConfigProtocol::Tcp,
                "UDP" => GenConfigProtocol::Udp,
                "ICMP" => GenConfigProtocol::Icmp,
                "HTTP" => GenConfigProtocol::Http,
                "RAW" => GenConfigProtocol::Raw,
                _ => {
                    eprintln!("What is case? {}", l3_proto);
                    GenConfigProtocol::Unknown
                }
            };
            gc.proto = proto;
        }

        if let Some(l4_sport) = &cfg.l4_sport {
            gc.l4_sport = *l4_sport;
        }

        if let Some(l4_dport) = &cfg.l4_dport {
            gc.l4_dport = *l4_dport;
        }

        let mut payload_part = cfg.payloads.trim().split('\n');
        while let Some(py) = payload_part.next() {
            let part: Vec<&str> = py.split(",").into_iter().map(|s| s).collect();

            if part.len() >= 1 {
                let rev = match bool::from_str(part[0]) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("Invaild sentense: {}", e);
                        continue;
                    }
                };
                let result = match part.len() {
                    1 => GenConfigPayload {
                        rev,
                        payload: None,
                        flags: None,
                    },
                    2..=3 => {
                        let hex_to_vec = |hex: &str| -> Option<Vec<u8>> {
                            if hex.len() % 2 != 0 {
                                return None;
                            }
                            (0..hex.len())
                                .step_by(2)
                                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                                .collect()
                        };

                        let py_result = if gc.proto == GenConfigProtocol::Http {
                            Some(part[1].as_bytes().to_vec())
                        } else {
                            hex_to_vec(part[1])
                        };

                        if let Some(hex_vec) = py_result {
                            let mut result = GenConfigPayload {
                                rev,
                                payload: Some(hex_vec),
                                flags: None,
                            };
                            if part.len() == 3 {
                                result.flags = Some(match u8::from_str_radix(part[2], 16) {
                                    Ok(k) => k,
                                    Err(_) => {
                                        fpcaps::general::TcpFlag::Syn
                                            | fpcaps::general::TcpFlag::Ack
                                    }
                                });
                            }
                            result
                        } else {
                            eprintln!("Can't dissect payload sentense: {}", part[1]);
                            continue;
                        }
                    }
                    _ => {
                        eprintln!("Can't dissect following sentense: {}", py);
                        continue;
                    }
                };
                gc.payloads.push(result);
            }
        }

        Ok(gc)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GenUndefConfig {
    l2_smac: Option<String>,
    l2_dmac: Option<String>,
    l3_saddr: Option<String>,
    l3_daddr: Option<String>,
    l3_proto: Option<String>,
    l4_sport: Option<u16>,
    l4_dport: Option<u16>,
    payloads: String,
}

impl GenUndefConfig {
    pub fn from_str(s: &str) -> Option<Self> {
        match toml::from_str(s) {
            Ok(o) => Some(o),
            Err(e) => {
                eprintln!("{:?}", e);
                None
            }
        }
    }

    pub fn from_file(path: &str) -> Option<Self> {
        match File::open(path) {
            Ok(mut p) => {
                let mut s = String::new();
                match p.read_to_string(&mut s) {
                    Ok(_) => Self::from_str(&s),
                    Err(e) => {
                        eprintln!("{:?}", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("{:?}", e);
                None
            }
        }
    }
}
