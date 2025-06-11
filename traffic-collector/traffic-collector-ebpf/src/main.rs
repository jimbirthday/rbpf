#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_cgroup_id,
        bpf_get_current_comm, bpf_ktime_get_ns, bpf_probe_read,
        bpf_probe_read_kernel,
    },
    macros::{kprobe, map},
    maps::HashMap,
    programs::ProbeContext,
};

use aya_log_ebpf::trace;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessInfoKey {
    pub cgroup_id: u64,    // 8 bytes
    pub pid: u32,          // 4 bytes
    pub comm: [u8; 8],     // 8 bytes - 存储进程名的前8个字符
    _pad: [u8; 4],         // 4 bytes padding to ensure 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessInfoValue {
    pub src_ip: u32,       // 4 bytes
    pub dst_ip: u32,       // 4 bytes
    pub src_port: u16,     // 2 bytes
    pub dst_port: u16,     // 2 bytes
    _pad: [u8; 4],         // 4 bytes padding to ensure 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStatsHeader {
    pub bytes_sent: u64,      // 8 bytes
    pub bytes_received: u64,  // 8 bytes
    pub last_activity: u64,   // 8 bytes
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStatsNetwork {
    pub src_ip: u32,          // 4 bytes
    pub dst_ip: u32,          // 4 bytes
    pub src_port: u16,        // 2 bytes
    pub dst_port: u16,        // 2 bytes
    pub direction: u32,       // 4 bytes
    _pad: [u8; 4],           // 4 bytes padding to ensure 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStats {
    pub header: TrafficStatsHeader,
    pub network: TrafficStatsNetwork,
}

#[repr(C)]
struct sock_common {
    skc_family: u16,     // 2 bytes - add family field
    skc_daddr: u32,      // 4 bytes
    skc_rcv_saddr: u32,  // 4 bytes
    skc_num: u16,        // 2 bytes
    skc_dport: u16,      // 2 bytes
    _pad: [u8; 4],       // 4 bytes padding to ensure 8-byte alignment
}

// 添加 IPv6 地址结构
#[repr(C)]
struct in6_addr {
    in6_u: [u8; 16],
}

// 添加 IPv6 套接字结构
#[repr(C)]
struct sock_common_v6 {
    skc_family: u16,
    skc_daddr: in6_addr,
    skc_rcv_saddr: in6_addr,
    skc_num: u16,
    skc_dport: u16,
    _pad: [u8; 4],
}

#[repr(C)]
struct sock {
    __sk_common: sock_common,
    // ... other fields
}

// 添加套接字族常量
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const AF_LOCAL: u16 = 1;
const AF_UNIX: u16 = 1;

#[map(name = "traffic_stats_0")]
static mut TRAFFIC_STATS_0: HashMap<ProcessInfoKey, TrafficStatsHeader> =
    HashMap::with_max_entries(600_000, 0);

#[map(name = "traffic_stats_1")]
static mut TRAFFIC_STATS_1: HashMap<ProcessInfoKey, TrafficStatsHeader> =
    HashMap::with_max_entries(600_000, 0);

#[map(name = "traffic_network_0")]
static mut TRAFFIC_NETWORK_0: HashMap<ProcessInfoKey, TrafficStatsNetwork> =
    HashMap::with_max_entries(600_000, 0);

#[map(name = "traffic_network_1")]
static mut TRAFFIC_NETWORK_1: HashMap<ProcessInfoKey, TrafficStatsNetwork> =
    HashMap::with_max_entries(600_000, 0);

#[map(name = "control_map")]
static mut CONTROL_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

// Replace the ipv4_to_string function with a simpler version that returns a byte slice
fn ipv4_to_bytes(ip: u32) -> [u8; 4] {
    [
        ((ip >> 24) & 0xFF) as u8,
        ((ip >> 16) & 0xFF) as u8,
        ((ip >> 8) & 0xFF) as u8,
        (ip & 0xFF) as u8,
    ]
}

fn get_socket_family_name(family: u16) -> &'static str {
    match family {
        AF_INET => "AF_INET",
        AF_INET6 => "AF_INET6",
        AF_LOCAL => "AF_UNIX",
        0x7f => "AF_LOCAL/UNIX",  // Common value for Unix domain sockets
        _ => "UNKNOWN",
    }
}

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match handle_traffic(ctx, true) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match handle_traffic(ctx, false) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn get_active_buffer() -> u32 {
    unsafe { CONTROL_MAP.get(&0).copied().unwrap_or(0) }
}

fn handle_traffic(ctx: ProbeContext, is_send: bool) -> Result<u32, u32> {
    let sock_ptr = ctx.arg::<*const sock>(0).ok_or(1u32)?;

    if sock_ptr.is_null() {
        trace!(&ctx, "sock_ptr is null");
        return Err(1);
    }

    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };

    trace!(&ctx, "Process info - pid: {}, cgroup_id: {}", pid, cgroup_id);

    let mut comm = [0u8; 8];
    match unsafe { bpf_get_current_comm() } {
        Ok(name) => {
            // 复制进程名到 comm 数组，最多8个字符
            let len = name.len().min(8);
            comm[..len].copy_from_slice(&name[..len]);
            // 确保字符串以null结尾
            if len < 8 {
                comm[len] = 0;
            }
        }
        Err(e) => {
            trace!(&ctx, "Failed to get process name: {}", e);
            // 使用固定字符串 "unknown"
            comm[0] = b'u';
            comm[1] = b'n';
            comm[2] = b'k';
            comm[3] = b'n';
            comm[4] = b'o';
            comm[5] = b'w';
            comm[6] = b'n';
            comm[7] = 0;
        }
    }

    let key = ProcessInfoKey {
        cgroup_id,
        pid,
        comm,
        _pad: [0u8; 4],
    };

    // 读取套接字族
    let family: u16 = unsafe {
        if let Ok(sock_val) = bpf_probe_read_kernel(sock_ptr) {
            sock_val.__sk_common.skc_family
        } else {
            trace!(&ctx, "Failed to read socket family");
            return Err(1);
        }
    };

    trace!(&ctx, "Socket family: {} (0x{:x})", get_socket_family_name(family), family);

    let (src_ip, dst_ip, src_port, dst_port) = match family {
        AF_INET => { // IPv4
            let sk_common = unsafe {
                if let Ok(sock_val) = bpf_probe_read_kernel(sock_ptr) {
                    sock_val.__sk_common
                } else {
                    trace!(&ctx, "Failed to read IPv4 socket");
                    return Err(1);
                }
            };
            trace!(&ctx, "IPv4 socket details - src: {}, dst: {}, sport: {}, dport: {}", 
                  sk_common.skc_rcv_saddr, sk_common.skc_daddr, 
                  sk_common.skc_num, sk_common.skc_dport);
            (sk_common.skc_rcv_saddr, sk_common.skc_daddr, sk_common.skc_num, sk_common.skc_dport)
        },
        AF_INET6 => { // IPv6
            let sk_common = unsafe {
                if let Ok(sock_val) = bpf_probe_read_kernel(sock_ptr.cast::<sock_common_v6>()) {
                    sock_val
                } else {
                    trace!(&ctx, "Failed to read IPv6 socket");
                    return Err(1);
                }
            };
            // 对于 IPv6，我们暂时只使用地址的前 4 字节
            let src_ip = u32::from_be_bytes([sk_common.skc_rcv_saddr.in6_u[0], 
                                           sk_common.skc_rcv_saddr.in6_u[1],
                                           sk_common.skc_rcv_saddr.in6_u[2],
                                           sk_common.skc_rcv_saddr.in6_u[3]]);
            let dst_ip = u32::from_be_bytes([sk_common.skc_daddr.in6_u[0],
                                           sk_common.skc_daddr.in6_u[1],
                                           sk_common.skc_daddr.in6_u[2],
                                           sk_common.skc_daddr.in6_u[3]]);
            trace!(&ctx, "IPv6 socket details - src: {}, dst: {}, sport: {}, dport: {}", 
                  src_ip, dst_ip, sk_common.skc_num, sk_common.skc_dport);
            (src_ip, dst_ip, sk_common.skc_num, sk_common.skc_dport)
        },
        AF_LOCAL | AF_UNIX => { // Unix domain socket
            let sk_common = unsafe {
                if let Ok(sock_val) = bpf_probe_read_kernel(sock_ptr) {
                    sock_val.__sk_common
                } else {
                    trace!(&ctx, "Failed to read Unix socket");
                    return Err(1);
                }
            };
            trace!(&ctx, "Unix socket details - src: {}, dst: {}, sport: {}, dport: {}", 
                  sk_common.skc_rcv_saddr, sk_common.skc_daddr, 
                  sk_common.skc_num, sk_common.skc_dport);
            (sk_common.skc_rcv_saddr, sk_common.skc_daddr, sk_common.skc_num, sk_common.skc_dport)
        },
        _ => {
            // 对于未知类型的套接字，我们也尝试读取基本信息
            let sk_common = unsafe {
                if let Ok(sock_val) = bpf_probe_read_kernel(sock_ptr) {
                    sock_val.__sk_common
                } else {
                    trace!(&ctx, "Failed to read unknown socket type");
                    return Err(1);
                }
            };
            trace!(&ctx, "Unknown socket type details - src: {}, dst: {}, sport: {}, dport: {}", 
                  sk_common.skc_rcv_saddr, sk_common.skc_daddr, 
                  sk_common.skc_num, sk_common.skc_dport);
            (sk_common.skc_rcv_saddr, sk_common.skc_daddr, sk_common.skc_num, sk_common.skc_dport)
        }
    };

    let src_ip_bytes = ipv4_to_bytes(src_ip);
    let dst_ip_bytes = ipv4_to_bytes(dst_ip);
    trace!(&ctx, "Network info - src: {}.{}.{}.{}:{}, dst: {}.{}.{}.{}:{}, direction: {}", 
          src_ip_bytes[0], src_ip_bytes[1], src_ip_bytes[2], src_ip_bytes[3], src_port,
          dst_ip_bytes[0], dst_ip_bytes[1], dst_ip_bytes[2], dst_ip_bytes[3], dst_port,
          if is_send { "send" } else { "recv" });

    let active = get_active_buffer();
    trace!(&ctx, "Active buffer: {}", active);

    let network = TrafficStatsNetwork {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        direction: if is_send { 0 } else { 1 },
        _pad: [0u8; 4],
    };

    let mut header = TrafficStatsHeader {
        bytes_sent: 0,
        bytes_received: 0,
        last_activity: 0,
    };

    unsafe {
        match active {
            0 => {
                if let Some(existing) = TRAFFIC_STATS_0.get(&key) {
                    header = *existing;
                }
            }
            1 => {
                if let Some(existing) = TRAFFIC_STATS_1.get(&key) {
                    header = *existing;
                }
            }
            _ => return Err(1),
        }
    }

    let size: u32 = ctx.arg(2).ok_or(1u32)?;
    trace!(&ctx, "Data size: {}", size);

    if is_send {
        header.bytes_sent = header.bytes_sent.saturating_add(size as u64);
        trace!(&ctx, "Updated bytes_sent: {}", header.bytes_sent);
    } else {
        header.bytes_received = header.bytes_received.saturating_add(size as u64);
        trace!(&ctx, "Updated bytes_received: {}", header.bytes_received);
    }

    header.last_activity = unsafe { bpf_ktime_get_ns() };

    unsafe {
        let header_result = match active {
            0 => TRAFFIC_STATS_0.insert(&key, &header, 0),
            1 => TRAFFIC_STATS_1.insert(&key, &header, 0),
            _ => Err(1),
        };
        if header_result.is_err() {
            return Err(1);
        }

        let network_result = match active {
            0 => TRAFFIC_NETWORK_0.insert(&key, &network, 0),
            1 => TRAFFIC_NETWORK_1.insert(&key, &network, 0),
            _ => Err(1),
        };
        if network_result.is_err() {
            return Err(1);
        }
    }

    Ok(0)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";
