#![no_std]
#![no_main]
#![feature(panic_info_message)]

use aya_ebpf::{macros::{kprobe, map}, programs::ProbeContext};
use aya_ebpf::maps::HashMap;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_log_ebpf::info;

#[kprobe]
pub fn traffic_collector(ctx: ProbeContext) -> u32 {
    match try_traffic_collector(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[map(name = "bytes_sent")]
static mut BYTES_SENT: HashMap<u32, u64> = HashMap::with_max_entries(32768, 0);

fn try_traffic_collector(ctx: ProbeContext) -> Result<u32, u32> {
    // 获取 tcp_sendmsg 的参数
    let size: u32 = ctx.arg(2).ok_or(0u32)?;
    
    // 获取当前进程 ID (tgid)
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    
    // 添加调试日志
    // info!(&ctx, "tcp_sendmsg called: pid={}, size={}", tgid, size);
    
    // 更新计数器
    unsafe {
        // 获取当前值
        let current = match BYTES_SENT.get(&tgid) {
            Some(val) => *val,
            None => 0,
        };
        
        // 计算新值
        let new_value = current + size as u64;
        
        // 更新值
        if let Err(e) = BYTES_SENT.insert(&tgid, &new_value, 0) {
            info!(&ctx, "Failed to update counter for pid={}: error={}", tgid, e);
            return Err(1);
        }
        
        // 验证更新是否成功
        if let Some(updated) = BYTES_SENT.get(&tgid) {
            // info!(&ctx, "Counter updated: pid={}, old={}, new={}", tgid, current, *updated);
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
