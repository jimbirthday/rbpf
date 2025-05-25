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
        
        writeln!(writer, "ebpf_traffic_bytes_sent{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            sent,
            timestamp.timestamp()
        )?;

        writeln!(writer, "ebpf_traffic_bytes_received{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            received,
            timestamp.timestamp()
        )?;

        writeln!(writer, "ebpf_traffic_bytes_total{{CGroup=\"{}\",PID=\"{}\",Process=\"{}\"}} {} {}",
            cgroup_name,
            process_info.pid,
            process_name,
            sent + received,
            timestamp.timestamp()
        )?;
    }

    // 写入IP流量统计
    for ((src_ip, dst_ip), bytes) in ip_traffic.iter() {
        writeln!(writer, "ebpf_ip_traffic_1m_stats{{sip=\"{}\",dip=\"{}\"}} {} {}",
            format_ip(*src_ip),
            format_ip(*dst_ip),
            bytes,
            timestamp.timestamp()
        )?;
    }

    writer.flush()?;
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
        let mut bytes_sent_map = None;
        let mut bytes_received_map = None;
        let mut ip_traffic_map = None;

        for (name, map) in maps {
            match name {
                "bytes_sent" => {
                    bytes_sent_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, u64>::try_from(map).unwrap());
                }
                "bytes_received" => {
                    bytes_received_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, u64>::try_from(map).unwrap());
                }
                "ip_traffic" => {
                    ip_traffic_map = Some(aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, u64>::try_from(map).unwrap());
                }
                _ => {}
            }
        }

        let mut bytes_sent_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, u64> = bytes_sent_map.expect("bytes_sent map not found");
        let mut bytes_received_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, u64> = bytes_received_map.expect("bytes_received map not found");
        let mut ip_traffic_map: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, u64> = ip_traffic_map.expect("ip_traffic map not found");
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
                // 获取当前所有进程的流量数据
                let mut process_traffic: HashMap<ProcessInfo, (u64, u64)> = HashMap::new();
                let mut ip_traffic: HashMap<(u32, u32), u64> = HashMap::new();
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

                // 获取IP流量统计
                for entry in ip_traffic_map.iter() {
                    match entry {
                        Ok((process_info, bytes)) => {
                            map_size += 1;
                            if bytes > 0 {
                                let key = (process_info.src_ip, process_info.dst_ip);
                                let entry = ip_traffic.entry(key).or_insert(0);
                                *entry += bytes;
                            }
                        }
                        Err(e) => {
                            error!("Error reading IP traffic map entry: {:?}", e);
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
                info!("Map usage: {}/327680 entries", map_size);
                if map_size > 30000 {
                    warn!("Map is approaching capacity limit!");
                }

                info!("Traffic stats for last minute:");
                info!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                    "CGroup", "PID", "Process", "Bytes Sent", "Bytes Received", "Total");
                
                if process_traffic.is_empty() {
                    info!("No traffic detected in the last minute");
                } else {
                    for (process_info, (sent, received)) in process_traffic.iter() {
                        let cgroup_name = get_cgroup_name(process_info.cgroup_id);
                        let process_name = get_process_name(&process_info.comm);
                        
                        info!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15}", 
                            cgroup_name,
                            process_info.pid,
                            process_name,
                            sent,
                            received,
                            sent + received);
                    }
                }

                info!("\nIP Traffic stats for last minute:");
                info!("{:<20} {:<20} {:<15}", "Source IP", "Destination IP", "Total Traffic");
                
                if ip_traffic.is_empty() {
                    info!("No IP traffic detected in the last minute");
                } else {
                    for ((src_ip, dst_ip), bytes) in ip_traffic.iter() {
                        info!("{:<20} {:<20} {:<15}", 
                            format_ip(*src_ip),
                            format_ip(*dst_ip),
                            bytes);
                    }
                }

                info!("\nTotal Traffic:");
                info!("{:<20} {}", "Sent:", total_sent);
                info!("{:<20} {}", "Received:", total_received);
                info!("{:<20} {}", "Total:", total_sent + total_received);

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

