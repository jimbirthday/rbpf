use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, warn, info, error};
use tokio::signal;
use tokio::time::{self, Duration};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use aya::Pod;

// 全局计数器
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);

// 定义进程信息结构，需要与 eBPF 程序中的结构体匹配
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessInfo {
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: [u8; 16],
}

// 实现 Pod trait
unsafe impl Pod for ProcessInfo {}

impl std::hash::Hash for ProcessInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.cgroup_id.hash(state);
        self.pid.hash(state);
        self.comm.hash(state);
    }
}

impl PartialEq for ProcessInfo {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_id == other.cgroup_id && 
        self.pid == other.pid && 
        self.comm == other.comm
    }
}

impl Eq for ProcessInfo {}

// 获取 cgroup 名称的辅助函数
fn get_cgroup_name(cgroup_id: u64) -> String {
    // 遍历 /sys/fs/cgroup 下的所有 cgroup 目录
    if let Ok(entries) = std::fs::read_dir("/sys/fs/cgroup") {
        for entry in entries.flatten() {
            if let Ok(entries) = std::fs::read_dir(entry.path()) {
                for cgroup in entries.flatten() {
                    let path = cgroup.path();
                    if path.is_dir() {
                        // 读取 cgroup.id 文件
                        if let Ok(id_str) = std::fs::read_to_string(path.join("cgroup.id")) {
                            if let Ok(id) = id_str.trim().parse::<u64>() {
                                if id == cgroup_id {
                                    return path.file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("unknown")
                                        .to_string();
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    format!("cgroup_{}", cgroup_id)
}

// 获取进程名的辅助函数
fn get_process_name(comm: &[u8; 16]) -> String {
    String::from_utf8_lossy(comm)
        .trim_end_matches('\0')
        .to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 设置日志级别为 debug 以获取更多信息
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    println!("Starting traffic collector...");

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    println!("Loading eBPF program...");
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/traffic-collector"
    )))?;
    
    // 初始化 eBPF logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    } else {
        info!("eBPF logger initialized successfully");
    }

    println!("Starting eBPF monitoring...");
    // 启动 eBPF 任务
    let ebpf_handle = tokio::spawn(async move {
        // 获取并加载程序
        let program_send: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into().unwrap();
        program_send.load().unwrap();
        program_send.attach("tcp_sendmsg", 0).unwrap();

        let program_recv: &mut KProbe = ebpf.program_mut("tcp_recvmsg").unwrap().try_into().unwrap();
        program_recv.load().unwrap();
        program_recv.attach("tcp_recvmsg", 0).unwrap();
        
        println!("eBPF programs attached successfully");

        // 初始化 maps
        let mut maps = ebpf.maps_mut();
        let mut bytes_sent_map = None;
        let mut bytes_received_map = None;

        for (name, map) in maps {
            match name {
                "bytes_sent" => {
                    bytes_sent_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, u64>::try_from(map).unwrap());
                }
                "bytes_received" => {
                    bytes_received_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, u64>::try_from(map).unwrap());
                }
                _ => {}
            }
        }

        let mut bytes_sent_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, u64> = bytes_sent_map.expect("bytes_sent map not found");
        let mut bytes_received_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, u64> = bytes_received_map.expect("bytes_received map not found");
        println!("Maps initialized successfully");

        let mut interval = time::interval(Duration::from_secs(60));
        println!("Starting traffic monitoring...");
        loop {
            interval.tick().await;
            
            // 获取当前所有进程的流量数据
            let mut process_traffic: HashMap<ProcessInfo, (u64, u64)> = HashMap::new();
            let mut total_sent: u64 = 0;
            let mut total_received: u64 = 0;
            let mut map_size: usize = 0;
            
            // 获取所有当前有流量的进程数据
            for entry in bytes_sent_map.iter() {
                match entry {
                    Ok((process_info, bytes)) => {
                        map_size += 1;
                        if bytes > 0 {
                            let entry = process_traffic.entry(process_info.clone()).or_insert((0, 0));
                            entry.0 = bytes;
                            total_sent += bytes;
                            debug!("Found sent traffic for cgroup={}, pid={}, comm={}: {} bytes", 
                                process_info.cgroup_id, 
                                process_info.pid,
                                get_process_name(&process_info.comm),
                                bytes);
                        }
                    }
                    Err(e) => {
                        error!("Error reading sent map entry: {:?}", e);
                        continue;
                    }
                }
            }

            for entry in bytes_received_map.iter() {
                match entry {
                    Ok((process_info, bytes)) => {
                        map_size += 1;
                        if bytes > 0 {
                            let entry = process_traffic.entry(process_info.clone()).or_insert((0, 0));
                            entry.1 = bytes;
                            total_received += bytes;
                            debug!("Found received traffic for cgroup={}, pid={}, comm={}: {} bytes", 
                                process_info.cgroup_id, 
                                process_info.pid,
                                get_process_name(&process_info.comm),
                                bytes);
                        }
                    }
                    Err(e) => {
                        error!("Error reading received map entry: {:?}", e);
                        continue;
                    }
                }
            }

            // 打印 map 使用情况
            println!("Map usage: {}/32768 entries", map_size);
            if map_size > 30000 {
                warn!("Map is approaching capacity limit!");
            }

            // 打印每个进程的流量
            println!("\nTraffic stats for last minute:");
            println!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                "CGroup", "PID", "Process", "Bytes Sent", "Bytes Received", "Total");
            println!("{:-<95}", "");
            
            if process_traffic.is_empty() {
                println!("No traffic detected in the last minute");
            } else {
                for (process_info, (sent, received)) in process_traffic.iter() {
                    let cgroup_name = get_cgroup_name(process_info.cgroup_id);
                    let process_name = get_process_name(&process_info.comm);
                    
                    println!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                        cgroup_name,
                        process_info.pid,
                        process_name,
                        format_bytes(*sent),
                        format_bytes(*received),
                        format_bytes(sent + received));
                    
                    // 重置计数器
                    match bytes_sent_map.remove(process_info) {
                        Ok(_) => debug!("Successfully reset sent counter for cgroup={}, pid={}", 
                            process_info.cgroup_id, process_info.pid),
                        Err(e) => {
                            if !e.to_string().contains("No such file or directory") {
                                error!("Failed to reset sent counter for cgroup={}, pid={}: {:?}", 
                                    process_info.cgroup_id, process_info.pid, e);
                            }
                        }
                    }
                    match bytes_received_map.remove(process_info) {
                        Ok(_) => debug!("Successfully reset received counter for cgroup={}, pid={}", 
                            process_info.cgroup_id, process_info.pid),
                        Err(e) => {
                            if !e.to_string().contains("No such file or directory") {
                                debug!("Failed to reset received counter for cgroup={}, pid={}: {:?}", 
                                    process_info.cgroup_id, process_info.pid, e);
                            }
                        }
                    }
                }
            }
            println!("{:-<95}", "");
            println!("Total Traffic:");
            println!("{:<20} {}", "Sent:", format_bytes(total_sent));
            println!("{:<20} {}", "Received:", format_bytes(total_received));
            println!("{:<20} {}", "Total:", format_bytes(total_sent + total_received));
            println!("{:-<95}", "\n");
        }
    });

    // 等待 Ctrl-C
    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    // 停止 eBPF 任务
    ebpf_handle.abort();

    Ok(())
}

// 添加一个辅助函数来格式化字节数
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

