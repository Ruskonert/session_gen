use std::io::Error;
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use clap::{Arg, ArgAction, Command};
use config::GenConfig;
use fpcaps::general::{IPProtocol, TcpFlag};
use fpcaps::preset::{catch_syn_ack_fp_preset, catch_syn_fp_preset};
use fpcaps::session::Session;
use fpcaps::tracer::{Tracer, TracerDirection};

use lazy_static::lazy_static;
use libc::c_int;
use libc::{close, sendto, sockaddr_ll};

use poll::Poll;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use util::{bind_to_interface, create_raw_socket, generate_ips, select_private_ip};

pub mod config;
pub mod poll;
mod util;

lazy_static! {
    pub static ref SENDED_PACKET: Mutex<u64> = Mutex::new(0);
}

fn send_payload(sockfd: c_int, payload: &[u8], sock_addr: &sockaddr_ll) -> Result<(), Error> {
    unsafe {
        let result = sendto(
            sockfd,
            payload as *const [u8] as *const _,
            payload.len(),
            0,
            sock_addr as *const sockaddr_ll as *const _,
            std::mem::size_of::<sockaddr_ll>() as u32,
        );
        if result < 0 {
            return Err(Error::last_os_error());
        }
        if let Ok(mut i) = SENDED_PACKET.lock() {
            *i += 1;
        }
    }
    Ok(())
}

fn benchmark_payload() {
    let mut last: u64 = 0;
    loop {
        if let Ok(p) = SENDED_PACKET.lock() {
            let count = *p - last;
            last = *p;
            println!("Benckmark Result => {} PPS, Total Packet: {}", count, *p);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn create_thread(
    sessions: Vec<Session>,
    payloads: Vec<(Vec<u8>, bool, u8)>, // payload, reverse, flags
    maximum_pps: f64,
    loop_count: usize,
    sockfd: c_int,
    sock_addr: sockaddr_ll,
    os_name: String,
    has_reset: bool,
) {
    let mut tracers = vec![];
    let mut payload_polls = vec![];
    let mut end_count = 0;
    let session_count = sessions.len();
    let busy_wait = unsafe { BUSY_MODE };

    let os_profile = catch_syn_fp_preset(&os_name);
    let ack_os_profile = catch_syn_ack_fp_preset(&os_name);

    if busy_wait {
        println!("!! Busy-mode is enabled, Be mindful of CPU resources");
    }

    for session in sessions {
        let mut tracer = Tracer::new_with_session(session);
        tracer.set_mode_record_packet(false); // we don't need to record the generated packet.

        /* Register OS info if exists */
        if let Some(os_profile) = &os_profile {
            println!("syn FP: {:?}", os_profile);
            tracer.regi_os(TcpFlag::Syn as u8, os_profile);
        }
        if let Some(os_profile) = &ack_os_profile {
            println!("syn+ack FP: {:?}", os_profile);
            tracer.regi_os(TcpFlag::Syn | TcpFlag::Ack, os_profile);
        }

        // Hello with 3-way-handshake
        for payload in tracer.sendp_handshake() {
            if let Err(error) = send_payload(sockfd, &payload, &sock_addr) {
                println!("{:?}", error);
                return;
            }
        }
        tracers.push(tracer);

        let pps = thread_rng().gen_range(maximum_pps / 2.0..maximum_pps);
        let mut payload_poll = Poll::new();
        for payload in payloads.clone() {
            payload_poll.push_data(payload);
        }
        payload_poll.set_per_second(pps);
        payload_poll.loop_count = loop_count;
        payload_poll.build();

        payload_polls.push(payload_poll);
    }
    loop {
        let end_time = Instant::now();
        for (idx, payload_poll) in payload_polls.iter_mut().enumerate() {
            let tracer = &mut tracers[idx];
            if let Some((payload, reverse, flags)) = payload_poll.poll() {
                if reverse == (tracer.direction() == TracerDirection::Forward) {
                    tracer.switch_direction(false);
                }

                if tracer.protocol() == IPProtocol::TCP {
                    tracer.as_session().l4_tcp_flags = flags;
                }

                for fin_payload in tracer.send(&payload, false) {
                    if let Err(error) = send_payload(sockfd, &fin_payload, &sock_addr) {
                        println!("Failed to send the packet, detail: {:?}", error);
                        break;
                    }
                }

                /* Try disconnect when all payloads are trasmitted */
                if has_reset && payload_poll.is_reset() {
                    for payload in tracer.sendp_handshake() {
                        if let Err(error) = send_payload(sockfd, &payload, &sock_addr) {
                            println!("{:?}", error);
                            return;
                        }
                    }
                }
            }

            if payload_poll.is_ended() {
                /* @@@ Communication is ended */
                if let Err(error) = send_payload(sockfd, &tracer.sendp_tcp_finish(), &sock_addr) {
                    println!("{:?}", error);
                    break;
                }
                tracer.switch_direction(false);
                if let Err(error) = send_payload(sockfd, &tracer.sendp_tcp_finish(), &sock_addr) {
                    println!("{:?}", error);
                    break;
                }
                end_count += 1;
            }

            if end_count == session_count {
                return;
            }
        }

        if !busy_wait {
            let elapsed_time = end_time.duration_since(Instant::now());
            let mics = elapsed_time.as_millis() as u64;
            if mics < 1000 {
                std::thread::sleep(Duration::from_millis(1000 - mics));
            }
        }
    }
}

static mut SESSION_COUNT: usize = 1000;
static mut HOST_PER_COUNT: usize = 2;
static mut THREAD_COUNT: usize = 2;
static mut INTERFACE_NAME: Option<String> = None;
static mut MAXIMUM_PPS: f64 = 0.75;
static mut LOOP_COUNT: usize = 1;
static mut BUSY_MODE: bool = false;
static mut SEED: usize = 0;

static mut SRC_MAC: Option<String> = None;
static mut DST_MAC: Option<String> = None;

fn main() {
    let matches = Command::new("session_gen")
        .version("1.0")
        .about("Session generator")
        .arg(
            Arg::new("session_count")
                .short('s')
                .long("session-count")
                .default_value("1000")
                .value_parser(clap::value_parser!(usize))
                .help("Number of sessions"),
        )
        .arg(
            Arg::new("thread")
                .short('t')
                .long("thread")
                .default_value("2")
                .value_parser(clap::value_parser!(usize))
                .help("Number of threads"),
        )
        .arg(
            Arg::new("iface")
                .short('i')
                .long("iface")
                .default_value("eth1")
                .help("Network interface name"),
        )
        .arg(
            Arg::new("pps")
                .short('p')
                .long("pps")
                .default_value("0.75")
                .value_parser(clap::value_parser!(f64))
                .help("The average PPS of packets sent per second by each session"),
        )
        .arg(
            Arg::new("busy_mode")
                .short('b')
                .long("busy-mode")
                .help("Enables busy mode")
                .action(ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("has_reset")
                .long("has-reset")
                .help("Set reset")
                .action(ArgAction::SetTrue)
                .required(false),
        )
        .arg(
            Arg::new("src")
                .long("src")
                .help("Set source mac")
                .default_value("00:11:33:44:55:66")
                .required(false),
        )
        .arg(
            Arg::new("dst")
                .long("dst")
                .help("Set destination mac")
                .default_value("a0:f5:09:7b:0a:8c")
                .required(false),
        )
        .arg(
            Arg::new("seed")
                .short('e')
                .long("seed")
                .default_value("0")
                .value_parser(clap::value_parser!(usize))
                .help("Seed for selecting specific randomized private IP"),
        )
        .arg(
            Arg::new("loop")
                .short('l')
                .long("loop")
                .default_value("1")
                .value_parser(clap::value_parser!(usize))
                .help("Number of loops"),
        )
        .arg(
            Arg::new("os")
                .short('o')
                .long("os")
                .default_value("")
                .help("Apply them with profile"),
        )
        .arg(
            Arg::new("preset")
                .long("preset")
                .default_value("")
                .help("Load preset TOML file"),
        )
        .get_matches();

    /* Dissects argument of program */
    unsafe {
        SESSION_COUNT = *matches.get_one("session_count").unwrap_or(&1000);
        THREAD_COUNT = *matches.get_one("thread").unwrap_or(&2);
        INTERFACE_NAME = Some(
            matches
                .get_one::<String>("iface")
                .map(|s| s.to_owned())
                .unwrap_or("eth1".to_string()),
        );
        MAXIMUM_PPS = *matches.get_one("pps").unwrap_or(&1.0);
        LOOP_COUNT = *matches.get_one("loop").unwrap_or(&1);
        BUSY_MODE = *matches.get_one("busy_mode").unwrap_or(&false);
        HOST_PER_COUNT = SESSION_COUNT / THREAD_COUNT;
        SRC_MAC = Some(
            matches
                .get_one::<String>("src")
                .map(|s| s.to_owned())
                .unwrap_or("00:11:33:44:55:66".to_string()),
        );

        DST_MAC = Some(
            matches
                .get_one::<String>("dst")
                .map(|s| s.to_owned())
                .unwrap_or("a0:f5:09:7b:0a:8c".to_string()),
        );

        SEED = *matches.get_one("seed").unwrap_or(&0);

        if HOST_PER_COUNT == 0 {
            THREAD_COUNT = 1;
            HOST_PER_COUNT = SESSION_COUNT;
        }
    }

    let mut sockfd_s = Vec::new();
    let mut thread_s = Vec::new();
    let mut remain = false;
    let mut rng = rand::thread_rng();
    let mut selected_rng = StdRng::seed_from_u64(unsafe { SEED } as u64);

    let os_name = matches.get_one("os").unwrap_or(&"".to_string()).to_owned();
    let has_reset = *matches.get_one("has_reset").unwrap_or(&false);
    let preset_path = matches
        .get_one("preset")
        .unwrap_or(&"".to_string())
        .to_owned();

    unsafe {
        let host_ips: usize = if SESSION_COUNT <= HOST_PER_COUNT {
            1
        } else {
            if SESSION_COUNT % HOST_PER_COUNT != 0 {
                remain = true;
                (SESSION_COUNT / HOST_PER_COUNT) + 1
            } else {
                SESSION_COUNT / HOST_PER_COUNT
            }
        };

        let cfg = if preset_path.len() > 0 {
            match GenConfig::from_path(&preset_path) {
                Ok(cfg) => {
                    if &cfg.l2_smac != &[0 as u8; 6] {
                        let mac = format!(
                            "{:02x}:{:02x}:{:02x}:{:02}:{:02x}:{:02x}",
                            cfg.l2_smac[0],
                            cfg.l2_smac[1],
                            cfg.l2_smac[2],
                            cfg.l2_smac[3],
                            cfg.l2_smac[4],
                            cfg.l2_smac[5],
                        );
                        SRC_MAC = Some(mac);
                        println!("Use preset Source MAC address: {:?}", SRC_MAC);
                    }
                    if &cfg.l2_dmac != &[0 as u8; 6] {
                        let mac = format!(
                            "{:02x}:{:02x}:{:02x}:{:02}:{:02x}:{:02x}",
                            cfg.l2_dmac[0],
                            cfg.l2_dmac[1],
                            cfg.l2_dmac[2],
                            cfg.l2_dmac[3],
                            cfg.l2_dmac[4],
                            cfg.l2_dmac[5],
                        );
                        DST_MAC = Some(mac);
                        println!("Use preset Destination MAC address: {:?}", DST_MAC);
                    }
                    Some(cfg)
                }
                Err(e) => {
                    panic!("{:?}", e);
                }
            }
        } else {
            None
        };

        let session_all_ips = if let Some(cfg) = &cfg {
            let mut v1 = generate_ips(
                &format!(
                    "{}.{}.{}.{}",
                    cfg.l3_saddr[0], cfg.l3_saddr[1], cfg.l3_saddr[2], cfg.l3_saddr[3]
                ),
                (SESSION_COUNT).try_into().unwrap(),
            );

            if &cfg.l3_daddr != &[0 as u8; 16] {
                let v2 = generate_ips(
                    &format!(
                        "{}.{}.{}.{}",
                        cfg.l3_daddr[0], cfg.l3_daddr[1], cfg.l3_daddr[2], cfg.l3_daddr[3]
                    ),
                    (host_ips).try_into().unwrap(),
                );
                v1.extend(v2);
            }
            v1
        } else {
            if SEED == 0 {
                select_private_ip((SESSION_COUNT + host_ips).try_into().unwrap(), 0, &mut rng)
            } else {
                select_private_ip(
                    (SESSION_COUNT + host_ips).try_into().unwrap(),
                    0,
                    &mut selected_rng,
                )
            }
        };
        for host_idx in 0..host_ips {
            let start_idx = HOST_PER_COUNT * host_idx;
            let end_idx = if host_idx + 1 == host_ips {
                if remain {
                    SESSION_COUNT
                } else {
                    HOST_PER_COUNT * (host_idx + 1)
                }
            } else {
                HOST_PER_COUNT * (host_idx + 1)
            };
            let mut sessions = vec![];
            println!(
                "Generating session session_idx ({}..{})",
                start_idx, end_idx
            );

            for session_idx in start_idx..end_idx {
                let port = rng.gen_range(10000..=60000);
                let mut session = if let Some(cfg) = &cfg {
                    match cfg.proto {
                        config::GenConfigProtocol::Raw => Session::create_ether(0x0800),
                        config::GenConfigProtocol::Tcp => Session::create_tcp(port, cfg.l4_dport),
                        config::GenConfigProtocol::Udp => Session::create_udp(port, cfg.l4_dport),
                        _ => {
                            panic!("Unsupport Protocol type during load the preset");
                        }
                    }
                } else {
                    Session::create_tcp(port, 80)
                };

                session.assign_src_ip(&session_all_ips[session_idx]);

                let host_idx = SESSION_COUNT + (session_idx % host_ips);
                session.assign_dst_ip(&session_all_ips[host_idx]);

                if let Some(src) = &SRC_MAC.to_owned() {
                    session.assign_src_mac(src);
                }

                if let Some(dst) = &DST_MAC.to_owned() {
                    session.assign_dst_mac(dst);
                }

                sessions.push(session);
            }

            let iface = INTERFACE_NAME.clone().unwrap();
            match create_raw_socket() {
                Ok(sockfd) => {
                    sockfd_s.push(sockfd);

                    let mut sockaddr_ll: sockaddr_ll = std::mem::zeroed();

                    if let Err(e) = bind_to_interface(sockfd, &iface, &mut sockaddr_ll) {
                        println!("Failed to bind the interface ({}), detail: {:?}", iface, e);
                        break;
                    }

                    let mut payloads = vec![];
                    if let Some(cfg) = &cfg {
                        for payload in &cfg.payloads {
                            let payload_raw = if let Some(p) = &payload.payload {
                                p.clone()
                            } else {
                                vec![]
                            };

                            let flags = if let Some(flags) = &payload.flags {
                                *flags
                            } else {
                                match cfg.proto {
                                    config::GenConfigProtocol::Tcp => TcpFlag::Syn | TcpFlag::Push,
                                    _ => 0,
                                }
                            };

                            payloads.push((payload_raw, payload.rev, flags));
                        }
                    } else {
                        let request_payload =
                        "POST /hello?param=<script>alert(\"Hello world!\");</script> HTTP/1.1\r\n"
                            .as_bytes()
                            .to_vec();
                        let response_payload = "HTTP/1.1 200 OK\r\n".as_bytes().to_vec();
                        payloads.push((request_payload, false, TcpFlag::Syn | TcpFlag::Push));
                        payloads.push((response_payload, true, TcpFlag::Syn | TcpFlag::Push));
                    }
                    let os_name = os_name.clone();
                    thread_s.push(thread::spawn(move || {
                        create_thread(
                            sessions,
                            payloads,
                            MAXIMUM_PPS,
                            LOOP_COUNT,
                            sockfd,
                            sockaddr_ll,
                            os_name,
                            has_reset,
                        );
                    }));
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(e) => {
                    println!("Failed to open the socket descriptor, detail: {:?}", e);
                    break;
                }
            }
        }
    }

    let _ = thread::spawn(|| benchmark_payload());

    for (idx, thread) in thread_s.into_iter().enumerate() {
        match thread.join() {
            Ok(()) => {}
            Err(err) => {
                println!(
                    "Failed to join the thread, thread id:{}, detail: {:?}",
                    idx, err
                );
            }
        }
        unsafe { close(sockfd_s[idx]) };
    }

    if let Ok(s) = SENDED_PACKET.lock() {
        println!("Result, Total packet sended: {}", *s);
    }
}
