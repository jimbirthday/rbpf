#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext};
use aya_ebpf::maps::HashMap;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_ktime_get_ns};
use aya_log_ebpf::info;

#[kprobe]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match try_traffic_collector_send(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn tcp_recvmsg(ctx: ProbeContext) -> u32 {
    match try_traffic_collector_recv(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

// 定义进程信息结构
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessInfo {
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: [u8; 16],  // 进程名，最多16字节
    pub src_ip: u32,     // 源IP地址
    pub dst_ip: u32,     // 目标IP地址
    _pad: u32,  // 添加填充以确保8字节对齐
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ip_traffic: u64,
    pub last_activity: u64,
}

impl ProcessInfo {
    fn new(cgroup_id: u64, pid: u32, comm: [u8; 16], src_ip: u32, dst_ip: u32) -> Self {
        ProcessInfo {
            cgroup_id,
            pid,
            comm,
            src_ip,
            dst_ip,
            _pad: 0,
        }
    }
}

#[map(name = "traffic_stats")]
static mut TRAFFIC_STATS: HashMap<ProcessInfo, TrafficStats> = HashMap::with_max_entries(600000, 0);

fn try_traffic_collector_send(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_sendmsg 的参数
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程信息
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    
    // 获取进程名
    let mut comm = [0u8; 16];
    match bpf_get_current_comm() {
        Ok(name) => {
            // 使用更安全的方式处理进程名
            let mut i = 0;
            while i < 15 {
                if i < name.len() {
                    comm[i] = name[i];
                } else {
                    comm[i] = 0;
                }
                i += 1;
            }
            comm[15] = 0;  // 确保以 null 结尾
        }
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    // 获取源IP和目标IP
    let src_ip: u32 = ctx.arg(0).ok_or(0u32)?;
    let dst_ip: u32 = ctx.arg(1).ok_or(0u32)?;
    
    let process_info = ProcessInfo::new(cgroup_id, pid, comm, src_ip, dst_ip);
    
    // 更新统计信息
    unsafe {
        let mut stats = match TRAFFIC_STATS.get(&process_info) {
            Some(val) => *val,
            None => TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                ip_traffic: 0,
                last_activity: 0,
            },
        };
        
        // 检查是否会发生溢出
        if stats.bytes_sent > u64::MAX - size as u64 {
            info!(&ctx, "Send counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, stats.bytes_sent, size);
            return Err(1);
        }
        
        if stats.ip_traffic > u64::MAX - size as u64 {
            info!(&ctx, "IP traffic counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, stats.ip_traffic, size);
            return Err(1);
        }
        
        // 更新统计信息
        stats.bytes_sent += size as u64;
        stats.ip_traffic += size as u64;
        stats.last_activity = bpf_ktime_get_ns();
        
        if let Err(e) = TRAFFIC_STATS.insert(&process_info, &stats, 0) {
            info!(&ctx, "Failed to update traffic stats for cgroup={}, pid={}: error={}", 
                cgroup_id, pid, e);
            return Err(1);
        }
    }

    Ok(0)
}

fn try_traffic_collector_recv(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_recvmsg 的参数
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程信息
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    
    // 获取进程名
    let mut comm = [0u8; 16];
    match bpf_get_current_comm() {
        Ok(name) => {
            // 使用更安全的方式处理进程名
            let mut i = 0;
            while i < 15 {
                if i < name.len() {
                    comm[i] = name[i];
                } else {
                    comm[i] = 0;
                }
                i += 1;
            }
            comm[15] = 0;  // 确保以 null 结尾
        }
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    // 获取源IP和目标IP
    let src_ip: u32 = ctx.arg(0).ok_or(0u32)?;
    let dst_ip: u32 = ctx.arg(1).ok_or(0u32)?;
    
    let process_info = ProcessInfo::new(cgroup_id, pid, comm, src_ip, dst_ip);
    
    // 更新统计信息
    unsafe {
        let mut stats = match TRAFFIC_STATS.get(&process_info) {
            Some(val) => *val,
            None => TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                ip_traffic: 0,
                last_activity: 0,
            },
        };
        
        // 检查是否会发生溢出
        if stats.bytes_received > u64::MAX - size as u64 {
            info!(&ctx, "Receive counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, stats.bytes_received, size);
            return Err(1);
        }
        
        if stats.ip_traffic > u64::MAX - size as u64 {
            info!(&ctx, "IP traffic counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, stats.ip_traffic, size);
            return Err(1);
        }
        
        // 更新统计信息
        stats.bytes_received += size as u64;
        stats.ip_traffic += size as u64;
        stats.last_activity = bpf_ktime_get_ns();
        
        if let Err(e) = TRAFFIC_STATS.insert(&process_info, &stats, 0) {
            info!(&ctx, "Failed to update traffic stats for cgroup={}, pid={}: error={}", 
                cgroup_id, pid, e);
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
