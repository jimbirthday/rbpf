#![no_std]
#![no_main]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext};
use aya_ebpf::maps::HashMap;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_cgroup_id, bpf_get_current_comm};
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

#[map(name = "bytes_sent")]
static mut BYTES_SENT: HashMap<ProcessInfo, u64> = HashMap::with_max_entries(327680, 0);

#[map(name = "bytes_received")]
static mut BYTES_RECEIVED: HashMap<ProcessInfo, u64> = HashMap::with_max_entries(327680, 0);

#[map(name = "ip_traffic")]
static mut IP_TRAFFIC: HashMap<ProcessInfo, u64> = HashMap::with_max_entries(327680, 0);

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
    
    // 更新发送计数器
    unsafe {
        let current = match BYTES_SENT.get(&process_info) {
            Some(val) => *val,
            None => 0,
        };
        
        // 检查是否会发生溢出
        if current > u64::MAX - size as u64 {
            info!(&ctx, "Send counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current, size);
            return Err(1);
        }
        
        let new_value = current + size as u64;
        
        if let Err(e) = BYTES_SENT.insert(&process_info, &new_value, 0) {
            info!(&ctx, "Failed to update send counter for cgroup={}, pid={}: error={}", 
                cgroup_id, pid, e);
            return Err(1);
        }

        // 更新IP流量统计
        let current_ip = match IP_TRAFFIC.get(&process_info) {
            Some(val) => *val,
            None => 0,
        };
        
        if current_ip > u64::MAX - size as u64 {
            info!(&ctx, "IP traffic counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current_ip, size);
            return Err(1);
        }
        
        let new_ip_value = current_ip + size as u64;
        
        if let Err(e) = IP_TRAFFIC.insert(&process_info, &new_ip_value, 0) {
            info!(&ctx, "Failed to update IP traffic counter for cgroup={}, pid={}: error={}", 
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
    
    // 更新接收计数器
    unsafe {
        let current = match BYTES_RECEIVED.get(&process_info) {
            Some(val) => *val,
            None => 0,
        };
        
        // 检查是否会发生溢出
        if current > u64::MAX - size as u64 {
            info!(&ctx, "Receive counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current, size);
            return Err(1);
        }
        
        let new_value = current + size as u64;
        
        if let Err(e) = BYTES_RECEIVED.insert(&process_info, &new_value, 0) {
            info!(&ctx, "Failed to update receive counter for cgroup={}, pid={}: error={}", 
                cgroup_id, pid, e);
            return Err(1);
        }

        // 更新IP流量统计
        let current_ip = match IP_TRAFFIC.get(&process_info) {
            Some(val) => *val,
            None => 0,
        };
        
        if current_ip > u64::MAX - size as u64 {
            info!(&ctx, "IP traffic counter overflow detected for cgroup={}, pid={}, current={}, adding={}", 
                cgroup_id, pid, current_ip, size);
            return Err(1);
        }
        
        let new_ip_value = current_ip + size as u64;
        
        if let Err(e) = IP_TRAFFIC.insert(&process_info, &new_ip_value, 0) {
            info!(&ctx, "Failed to update IP traffic counter for cgroup={}, pid={}: error={}", 
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
