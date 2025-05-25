use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, warn, info, error};
use tokio::signal;
use tokio::time::{self, Duration, sleep_until, Instant};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Command;
use std::path::Path;
use aya::Pod;
use chrono::{DateTime, Local, Timelike};
use env_logger::Builder;
use std::io::Write;
use std::fs::{self, File, OpenOptions};
use std::io::BufWriter;

// 全局计数器
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);

// 清理阈值常量
const INACTIVE_THRESHOLD_NS: u64 = 30_000_000_000; // 30秒
const GRACE_PERIOD_NS: u64 = 10_000_000_000; // 10秒
const FORCE_CLEANUP_THRESHOLD: usize = 400_000; // 强制清理阈值
const WARNING_THRESHOLD: usize = 450_000; // 警告阈值

// 定义进程信息结构，需要与 eBPF 程序中的结构体匹配
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessInfo {
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: [u8; 16],
    pub src_ip: u32,     // 源IP地址
    pub dst_ip: u32,     // 目标IP地址
    _pad: u32,  // 添加填充以确保8字节对齐
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ip_traffic: u64,
    pub last_activity: u64,
}

// 实现 Pod trait
unsafe impl Pod for ProcessInfo {}
unsafe impl Pod for TrafficStats {}

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
    // 找到第一个 null 字节的位置
    let null_pos = comm.iter().position(|&x| x == 0).unwrap_or(16);
    // 只转换到 null 字节之前的内容
    String::from_utf8_lossy(&comm[..null_pos]).to_string()
}

// 添加IP地址格式化函数
fn format_ip(ip: u32) -> String {
    let octets = [
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF,
    ];
    format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3])
}

// 添加写入日志文件的函数
fn write_stats_to_file(
    process_traffic: &HashMap<ProcessInfo, (u64, u64)>,
    ip_traffic: &HashMap<(u32, u32), u64>,
    total_sent: u64,
    total_received: u64,
    timestamp: DateTime<Local>,
) -> anyhow::Result<()> {
    // 确保日志目录存在
    let log_dir = Path::new("/var/log/mx-cIndicator");
    if !log_dir.exists() {
        fs::create_dir_all(log_dir)?;
    }

    // 创建日志文件名，使用时间戳
    let filename = format!("{}/traffic_stats_{}.prom", 
        log_dir.display(),
        timestamp.format("%Y%m%d_%H%M%S")
    );

    // 打开文件用于写入
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(false)
        .open(&filename)?;
    let mut writer = BufWriter::new(file);

    // 写入进程流量统计
    for (process_info, (sent, received)) in process_traffic.iter() {
        let cgroup_name = get_cgroup_name(process_info.cgroup_id);
        let process_name = get_process_name(&process_info.comm);
        
        writeln!(writer, "ebpf_traffic_bytes_sent{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            sent
        )?;

        writeln!(writer, "ebpf_traffic_bytes_received{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            received
        )?;

        writeln!(writer, "ebpf_traffic_bytes_total{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            sent + received
        )?;
    }

    // 写入IP流量统计
    // 合并源IP和目标IP的流量统计
    let mut ip_agg: HashMap<u32, u64> = HashMap::new();
    
    for ((src_ip, dst_ip), bytes) in ip_traffic.iter() {
        // 聚合源IP流量
        *ip_agg.entry(*src_ip).or_insert(0) += bytes;
        // 聚合目标IP流量
        *ip_agg.entry(*dst_ip).or_insert(0) += bytes;
    }

    // 写入合并后的IP流量统计
    for (ip, bytes) in ip_agg.iter() {
        writeln!(writer, "ebpf_ip_traffic_1m_stats{{ip=\"{}\"}} {}",
            format_ip(*ip),
            bytes
        )?;
    }

    writer.flush()?;
    Ok(())
}

// 添加清理函数
fn cleanup_inactive_entries(
    traffic_stats_map: &mut aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, TrafficStats>,
) -> anyhow::Result<()> {
    let mut current_time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut current_time);
    }
    let current_time_ns = (current_time.tv_sec as u64 * 1_000_000_000) + (current_time.tv_nsec as u64);
    
    // 获取所有需要清理的条目
    let mut to_cleanup = Vec::new();
    let mut total_entries = 0;
    
    // 收集所有条目并按最后活动时间排序
    let mut entries_by_time: Vec<(ProcessInfo, u64)> = Vec::new();
    
    for entry in traffic_stats_map.iter() {
        match entry {
            Ok((process_info, stats)) => {
                total_entries += 1;
                entries_by_time.push((process_info.clone(), stats.last_activity));
            }
            Err(e) => {
                error!("Error reading traffic stats map entry: {:?}", e);
                continue;
            }
        }
    }
    
    // 如果总条目数超过强制清理阈值，清理最旧的条目
    if total_entries > FORCE_CLEANUP_THRESHOLD {
        // 按最后活动时间排序
        entries_by_time.sort_by(|a, b| a.1.cmp(&b.1));
        
        // 计算需要清理的条目数
        let entries_to_clean = total_entries - FORCE_CLEANUP_THRESHOLD;
        
        // 清理最旧的条目
        for (process_info, _) in entries_by_time.iter().take(entries_to_clean) {
            to_cleanup.push(process_info.clone());
        }
        
        warn!("Forcing cleanup of {} oldest entries due to high map usage", entries_to_clean);
    } else {
        // 常规清理：检查不活跃条目
        for (process_info, last_activity) in entries_by_time {
            // 检查是否超过不活跃阈值
            if current_time_ns.saturating_sub(last_activity) > INACTIVE_THRESHOLD_NS {
                // 获取当前统计信息
                match traffic_stats_map.get(&process_info, 0) {
                    Ok(stats) => {
                        // 如果字节数为0或者超过宽限期，就清理
                        if (stats.bytes_sent == 0 && stats.bytes_received == 0) || 
                           current_time_ns.saturating_sub(last_activity) > (INACTIVE_THRESHOLD_NS + GRACE_PERIOD_NS) {
                            to_cleanup.push(process_info);
                        }
                    }
                    Err(e) => {
                        error!("Failed to get traffic stats for cleanup: {:?}", e);
                        continue;
                    }
                }
            }
        }
    }
    
    // 执行清理
    for process_info in to_cleanup {
        if let Err(e) = traffic_stats_map.remove(&process_info) {
            error!("Failed to remove traffic stats entry: {:?}", e);
        }
        debug!("Cleaned up inactive entry for cgroup={}, pid={}", 
            process_info.cgroup_id, 
            process_info.pid);
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 设置日志格式和级别
    let mut builder = Builder::from_default_env();
    builder
        .format(|buf, record| {
            // 对于统计信息的特殊处理
            if record.args().to_string().contains("Traffic stats") {
                writeln!(buf, "\n{}", record.args())
            } else if record.args().to_string().contains("Total Traffic") {
                writeln!(buf, "\n{}", record.args())
            } else if record.args().to_string().contains("Map usage") {
                writeln!(buf, "\n{}", record.args())
            } else if record.args().to_string().contains("IP Traffic stats") {
                writeln!(buf, "\n{}", record.args())
            } else if record.args().to_string().contains("-----") {
                // 跳过分隔线的日志记录
                Ok(())
            } else {
                writeln!(buf,
                    "{} [{}] - {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    record.level(),
                    record.args()
                )
            }
        })
        .filter(None, log::LevelFilter::Info)
        .init();

    info!("Starting traffic collector...");

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

    info!("Loading eBPF program...");
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

    info!("Starting eBPF monitoring...");
    // 启动 eBPF 任务
    let ebpf_handle = tokio::spawn(async move {
        // 获取并加载程序
        let program_send: &mut KProbe = ebpf.program_mut("tcp_sendmsg").unwrap().try_into().unwrap();
        program_send.load().unwrap();
        program_send.attach("tcp_sendmsg", 0).unwrap();

        let program_recv: &mut KProbe = ebpf.program_mut("tcp_recvmsg").unwrap().try_into().unwrap();
        program_recv.load().unwrap();
        program_recv.attach("tcp_recvmsg", 0).unwrap();
        
        info!("eBPF programs attached successfully");

        // 初始化 maps
        let mut maps = ebpf.maps_mut();
        let mut traffic_stats_map = None;

        for (name, map) in maps {
            match name {
                "traffic_stats" => {
                    traffic_stats_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, TrafficStats>::try_from(map).unwrap());
                }
                _ => {}
            }
        }

        let mut traffic_stats_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, TrafficStats> = 
            traffic_stats_map.expect("traffic_stats map not found");
        info!("Maps initialized successfully");

        println!("Starting traffic monitoring...");
        let mut last_print_time = Local::now();
        
        loop {
            // 计算下一个整分钟的时间
            let now = Local::now();
            let next_minute = if now.second() == 0 {
                now
            } else {
                now + chrono::Duration::seconds(60 - now.second() as i64)
            };
            
            // 等待到下一个整分钟
            let wait_duration = (next_minute - now).num_milliseconds() as u64;
            if wait_duration > 0 {
                sleep_until(Instant::now() + Duration::from_millis(wait_duration)).await;
            }

            // 获取当前时间
            let current_time = Local::now();
            
            // 只有当距离上次打印超过1分钟时才打印统计信息
            if (current_time - last_print_time).num_seconds() >= 60 {
                // 执行清理
                if let Err(e) = cleanup_inactive_entries(&mut traffic_stats_map) {
                    error!("Failed to cleanup inactive entries: {}", e);
                }
                
                // 获取当前所有进程的流量数据
                let mut process_traffic: HashMap<ProcessInfo, (u64, u64)> = HashMap::new();
                let mut ip_traffic: HashMap<(u32, u32), u64> = HashMap::new();
                let mut total_sent: u64 = 0;
                let mut total_received: u64 = 0;
                let mut unique_processes: std::collections::HashSet<ProcessInfo> = std::collections::HashSet::new();
                
                // 获取所有当前有流量的进程数据
                for entry in traffic_stats_map.iter() {
                    match entry {
                        Ok((process_info, stats)) => {
                            unique_processes.insert(process_info.clone());
                            if stats.bytes_sent > 0 || stats.bytes_received > 0 {
                                process_traffic.insert(process_info.clone(), (stats.bytes_sent, stats.bytes_received));
                                total_sent += stats.bytes_sent;
                                total_received += stats.bytes_received;
                                
                                // 更新IP流量统计
                                if stats.ip_traffic > 0 {
                                    let key = (process_info.src_ip, process_info.dst_ip);
                                    let entry = ip_traffic.entry(key).or_insert(0);
                                    *entry += stats.ip_traffic;
                                }
                                
                                debug!("Found traffic for cgroup={}, pid={}, comm={}: sent={}, received={}", 
                                    process_info.cgroup_id, 
                                    process_info.pid,
                                    get_process_name(&process_info.comm),
                                    stats.bytes_sent,
                                    stats.bytes_received);
                            }
                        }
                        Err(e) => {
                            error!("Error reading traffic stats map entry: {:?}", e);
                            continue;
                        }
                    }
                }

                // 写入统计信息到文件
                if let Err(e) = write_stats_to_file(
                    &process_traffic,
                    &ip_traffic,
                    total_sent,
                    total_received,
                    current_time,
                ) {
                    error!("Failed to write stats to file: {}", e);
                }

                // 打印统计信息
                let map_size = unique_processes.len();
                info!("Map usage: {}/600000 entries", map_size);
                if map_size > WARNING_THRESHOLD {
                    warn!("Map is approaching capacity limit!");
                }

                info!("Traffic stats for last minute:");
                debug!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                    "CGroup", "PID", "Process", "Bytes Sent", "Bytes Received", "Total");
                
                if process_traffic.is_empty() {
                    debug!("No traffic detected in the last minute");
                } else {
                    for (process_info, (sent, received)) in process_traffic.iter() {
                        let cgroup_name = get_cgroup_name(process_info.cgroup_id);
                        let process_name = get_process_name(&process_info.comm);
                        
                        debug!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                            cgroup_name,
                            process_info.pid,
                            process_name,
                            sent,
                            received,
                            sent + received);
                    }
                }

                debug!("\nIP Traffic stats for last minute:");
                debug!("{:<20} {:<20} {:<15}", "Source IP", "Destination IP", "Total Traffic");
                
                if ip_traffic.is_empty() {
                    info!("No IP traffic detected in the last minute");
                } else {
                    for ((src_ip, dst_ip), bytes) in ip_traffic.iter() {
                        debug!("{:<20} {:<20} {:<15}", 
                            format_ip(*src_ip),
                            format_ip(*dst_ip),
                            bytes);
                    }
                }

                info!("\nTotal Traffic:");
                // 计算每秒速率（假设是1分钟的数据）
                let sent_rate = total_sent as f64 / 60.0;
                let received_rate = total_received as f64 / 60.0;
                let total_rate = (total_sent + total_received) as f64 / 60.0;

                // 转换函数
                fn format_bytes(bytes: u64) -> String {
                    if bytes >= 1_073_741_824 {
                        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
                    } else if bytes >= 1_048_576 {
                        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
                    } else if bytes >= 1024 {
                        format!("{:.2} KB", bytes as f64 / 1024.0)
                    } else {
                        format!("{} B", bytes)
                    }
                }

                fn format_rate(bytes_per_sec: f64) -> String {
                    if bytes_per_sec >= 1_073_741_824.0 {
                        format!("{:.2} GB/s", bytes_per_sec / 1_073_741_824.0)
                    } else if bytes_per_sec >= 1_048_576.0 {
                        format!("{:.2} MB/s", bytes_per_sec / 1_048_576.0)
                    } else if bytes_per_sec >= 1024.0 {
                        format!("{:.2} KB/s", bytes_per_sec / 1024.0)
                    } else {
                        format!("{:.2} B/s", bytes_per_sec)
                    }
                }

                info!("{:<20} {} ({} bytes)", "Sent:", format_bytes(total_sent), total_sent);
                info!("{:<20} {} ({} bytes)", "Received:", format_bytes(total_received), total_received);
                info!("{:<20} {} ({} bytes)", "Total:", format_bytes(total_sent + total_received), total_sent + total_received);
                info!("{:<20} {}", "Send Rate:", format_rate(sent_rate));
                info!("{:<20} {}", "Receive Rate:", format_rate(received_rate));
                info!("{:<20} {}", "Total Rate:", format_rate(total_rate));

                // 更新上次打印时间
                last_print_time = current_time;
            }
        }
    });

    // 等待 Ctrl-C
    let ctrl_c = signal::ctrl_c();
    info!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    info!("Exiting...");

    // 停止 eBPF 任务
    ebpf_handle.abort();

    Ok(())
}

