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
    pub cgroup_id: u64,    // 8 bytes
    pub pid: u32,          // 4 bytes
    pub fd: u32,           // 4 bytes
    pub comm: [u8; 16],    // 16 bytes
    pub src_ip: u32,       // 4 bytes
    pub dst_ip: u32,       // 4 bytes
    _pad: [u8; 8],         // 8 bytes padding to ensure 8-byte alignment
}

// 定义流量统计结构
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TrafficStats {
    pub bytes_sent: u64,      // 8 bytes
    pub bytes_received: u64,  // 8 bytes
    pub last_activity: u64,   // 8 bytes
    pub src_ip: u64,          // 8 bytes
    pub dst_ip: u64,          // 8 bytes
    pub direction: u64,       // 8 bytes
}

// 双缓冲区的流量统计映射
#[map(name = "traffic_stats_0")]
static mut TRAFFIC_STATS_0: HashMap<ProcessInfo, TrafficStats> = HashMap::with_max_entries(600000, 0);

#[map(name = "traffic_stats_1")]
static mut TRAFFIC_STATS_1: HashMap<ProcessInfo, TrafficStats> = HashMap::with_max_entries(600000, 0);

// 控制映射，用于指示当前活跃的缓冲区
#[map(name = "control_map")]
static mut CONTROL_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);

fn get_active_buffer() -> u32 {
    unsafe {
        match CONTROL_MAP.get(&0) {
            Some(&index) => index,
            None => 0, // 默认使用第一个缓冲区
        }
    }
}

fn try_traffic_collector_send(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_sendmsg 的参数
    let sock: u64 = ctx.arg(0).ok_or(0u32)?;  // 获取socket指针
    let fd: u32 = (sock & 0xFFFFFFFF) as u32;  // 从socket指针中提取fd
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程信息
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    
    // 获取进程名
    let mut comm = [0u8; 16];
    match bpf_get_current_comm() {
        Ok(name) => {
            let mut i = 0;
            while i < 15 {
                if i < name.len() {
                    comm[i] = name[i];
                } else {
                    comm[i] = 0;
                }
                i += 1;
            }
            comm[15] = 0;
        }
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    // 获取源IP和目标IP
    let src_ip: u32 = ctx.arg(1).ok_or(0u32)?;
    let dst_ip: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 创建 ProcessInfo 结构体
    let process_info = ProcessInfo {
        cgroup_id,
        pid,
        fd,
        comm,
        src_ip,
        dst_ip,
        _pad: [0u8; 8],
    };
    
    // 获取当前活跃的缓冲区
    let active_buffer = get_active_buffer();
    
    // 更新统计信息
    unsafe {
        let stats = match active_buffer {
            0 => TRAFFIC_STATS_0.get(&process_info),
            1 => TRAFFIC_STATS_1.get(&process_info),
            _ => None,
        };
        
        let mut current_stats = match stats {
            Some(&val) => val,
            None => TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: 0,
                src_ip: src_ip as u64,
                dst_ip: dst_ip as u64,
                direction: 0,
            },
        };
        
        // 检查是否会发生溢出
        if current_stats.bytes_sent > u64::MAX - size as u64 {
            info!(&ctx, "Send counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current_stats.bytes_sent, size);
            return Err(1);
        }
        
        // 更新统计信息
        current_stats.bytes_sent += size as u64;
        current_stats.last_activity = bpf_ktime_get_ns();
        current_stats.direction = 0; // 发送方向
        
        // 根据活跃缓冲区更新数据
        let result = match active_buffer {
            0 => TRAFFIC_STATS_0.insert(&process_info, &current_stats, 0),
            1 => TRAFFIC_STATS_1.insert(&process_info, &current_stats, 0),
            _ => Err(1),
        };
        
        if let Err(e) = result {
            info!(&ctx, "Failed to update traffic stats for cgroup={}, pid={}: error={}", 
                cgroup_id, pid, e);
            return Err(1);
        }
    }

    Ok(0)
}

fn try_traffic_collector_recv(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_recvmsg 的参数
    let sock: u64 = ctx.arg(0).ok_or(0u32)?;  // 获取socket指针
    let fd: u32 = (sock & 0xFFFFFFFF) as u32;  // 从socket指针中提取fd
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程信息
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    
    // 获取进程名
    let mut comm = [0u8; 16];
    match bpf_get_current_comm() {
        Ok(name) => {
            let mut i = 0;
            while i < 15 {
                if i < name.len() {
                    comm[i] = name[i];
                } else {
                    comm[i] = 0;
                }
                i += 1;
            }
            comm[15] = 0;
        }
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    // 获取源IP和目标IP
    let src_ip: u32 = ctx.arg(1).ok_or(0u32)?;
    let dst_ip: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 创建 ProcessInfo 结构体
    let process_info = ProcessInfo {
        cgroup_id,
        pid,
        fd,
        comm,
        src_ip,
        dst_ip,
        _pad: [0u8; 8],
    };
    
    // 获取当前活跃的缓冲区
    let active_buffer = get_active_buffer();
    
    // 更新统计信息
    unsafe {
        let stats = match active_buffer {
            0 => TRAFFIC_STATS_0.get(&process_info),
            1 => TRAFFIC_STATS_1.get(&process_info),
            _ => None,
        };
        
        let mut current_stats = match stats {
            Some(&val) => val,
            None => TrafficStats {
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: 0,
                src_ip: src_ip as u64,
                dst_ip: dst_ip as u64,
                direction: 1,
            },
        };
        
        // 检查是否会发生溢出
        if current_stats.bytes_received > u64::MAX - size as u64 {
            info!(&ctx, "Receive counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current_stats.bytes_received, size);
            return Err(1);
        }
        
        // 更新统计信息
        current_stats.bytes_received += size as u64;
        current_stats.last_activity = bpf_ktime_get_ns();
        current_stats.direction = 1; // 接收方向
        
        // 根据活跃缓冲区更新数据
        let result = match active_buffer {
            0 => TRAFFIC_STATS_0.insert(&process_info, &current_stats, 0),
            1 => TRAFFIC_STATS_1.insert(&process_info, &current_stats, 0),
            _ => Err(1),
        };
        
        if let Err(e) = result {
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
