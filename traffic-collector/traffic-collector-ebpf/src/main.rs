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
pub struct ProcessInfo {
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: [u8; 16],  // 进程名，最多16字节
}

#[map(name = "bytes_sent")]
static mut BYTES_SENT: HashMap<ProcessInfo, u64> = HashMap::with_max_entries(32768, 0);

#[map(name = "bytes_received")]
static mut BYTES_RECEIVED: HashMap<ProcessInfo, u64> = HashMap::with_max_entries(32768, 0);

fn try_traffic_collector_send(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_sendmsg 的参数
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程信息
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    
    // 获取进程名
    let comm = match bpf_get_current_comm() {
        Ok(name) => name,
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    let process_info = ProcessInfo {
        cgroup_id,
        pid,
        comm,
    };
    
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
    let comm = match bpf_get_current_comm() {
        Ok(name) => name,
        Err(e) => {
            info!(&ctx, "Failed to get process name: {}", e);
            return Err(1);
        }
    };
    
    let process_info = ProcessInfo {
        cgroup_id,
        pid,
        comm,
    };
    
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
