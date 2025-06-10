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
use std::io::BufReader;
use std::io::prelude::*;
use serde_json::Value;
use clap::Parser;
use std::io::Read;
use glob::Pattern;
use serde::{Deserialize, Serialize};

/// 流量收集器配置
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 日志文件目录
    #[arg(short = 'l', long, default_value = "/var/log/mx-cIndicator")]
    log_dir: String,

    /// 日志保留天数（0表示不清理）
    #[arg(short = 'd', long, default_value = "7")]
    log_retention_days: u64,

    /// 日志级别 (debug, info, warn, error)
    #[arg(short = 'v', long, default_value = "info")]
    log_level: String,

    /// 统计时长（秒），debug模式下默认为10秒
    #[arg(short = 't', long)]
    stats_duration: Option<u64>,

    /// 规则文件路径
    #[arg(short = 'r', long, default_value = "rules.json")]
    rules_file: String,
}

// 定义进程信息结构，需要与 eBPF 程序中的结构体匹配
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProcessInfo {
    pub cgroup_id: u64,
    pub pid: u32,
    pub comm: [u8; 16],
    pub src_ip: u32,     // 源IP地址
    pub dst_ip: u32,     // 目标IP地址
    _pad: u32,  // 添加填充以确保8字节对齐
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TrafficStats {
    pub bytes_sent: u64,      // 8 bytes
    pub bytes_received: u64,  // 8 bytes
    pub last_activity: u64,   // 8 bytes
    pub src_ip: u64,          // 8 bytes (包含 src_ip 和 padding)
    pub dst_ip: u64,          // 8 bytes (包含 dst_ip 和 padding)
    pub direction: u64,       // 8 bytes (包含 direction 和 padding)
}

// 实现 Pod trait
unsafe impl Pod for ProcessInfo {}
unsafe impl Pod for TrafficStats {}

impl std::hash::Hash for ProcessInfo {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.cgroup_id.hash(state);
        self.pid.hash(state);
        self.comm.hash(state);
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
    }
}

impl PartialEq for ProcessInfo {
    fn eq(&self, other: &Self) -> bool {
        self.cgroup_id == other.cgroup_id && 
        self.pid == other.pid && 
        self.comm == other.comm &&
        self.src_ip == other.src_ip &&
        self.dst_ip == other.dst_ip
    }
}

impl Eq for ProcessInfo {}

// 获取 cgroup 名称的辅助函数
fn get_cgroup_name(cgroup_id: u64) -> String {
    format!("cgroup_{}", cgroup_id)
}

// 获取进程名的辅助函数
fn get_process_name(comm: &[u8; 16]) -> String {
    let null_pos = comm.iter().position(|&x| x == 0).unwrap_or(16);
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

// 定义规则结构
#[derive(Debug, Serialize, Deserialize)]
struct Rule {
    #[serde(default)]
    cgroup: String,
    #[serde(default)]
    process: String,
    #[serde(default)]
    blacklist_ips: Vec<String>,
}

// 加载规则
fn load_rules(rules_file: &str) -> anyhow::Result<Vec<Rule>> {
    let mut file = File::open(rules_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let rules: Vec<Rule> = serde_json::from_str(&contents)?;
    Ok(rules)
}

// 检查IP是否在黑名单中
fn is_ip_blacklisted(ip: u32, blacklist: &[String]) -> bool {
    let ip_str = format_ip(ip);
    blacklist.iter().any(|pattern| {
        if let Ok(pat) = Pattern::new(pattern) {
            pat.matches(&ip_str)
        } else {
            false
        }
    })
}

// 检查进程是否匹配规则
fn is_process_matched(process_name: &str, cgroup_name: &str, rule: &Rule) -> bool {
    // 如果规则中没有指定进程名和cgroup，则匹配所有
    if rule.process.is_empty() && rule.cgroup.is_empty() {
        return true;
    }

    // 检查进程名
    let process_matched = if !rule.process.is_empty() {
        if let Ok(pat) = Pattern::new(&rule.process) {
            pat.matches(process_name)
        } else {
            false
        }
    } else {
        true
    };

    // 检查cgroup
    let cgroup_matched = if !rule.cgroup.is_empty() {
        if let Ok(pat) = Pattern::new(&rule.cgroup) {
            pat.matches(cgroup_name)
        } else {
            false
        }
    } else {
        true
    };

    process_matched && cgroup_matched
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    let mut builder = Builder::from_default_env();
    builder.filter(None, log::LevelFilter::Info).init();

    // 设置统计时长
    let stats_duration = if args.log_level == "debug" {
        args.stats_duration.unwrap_or(10) // debug模式下默认10秒
    } else {
        args.stats_duration.unwrap_or(60) // 其他模式默认60秒
    };
    info!("Statistics duration set to {} seconds", stats_duration);
    info!("Using rules file: {}", args.rules_file);

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    info!("Starting eBPF monitoring...");
    
    // 获取并加载程序
    let mut ebpf = match aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/traffic-collector"
    ))) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            error!("Failed to load eBPF program: {}", e);
            return Ok(());
        }
    };
    
    // 初始化 eBPF logger
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    } else {
        info!("eBPF logger initialized successfully");
    }

    let program_send: &mut KProbe = match ebpf.program_mut("tcp_sendmsg") {
        Some(prog) => match prog.try_into() {
            Ok(prog) => prog,
            Err(e) => {
                error!("Failed to convert tcp_sendmsg program: {}", e);
                return Ok(());
            }
        },
        None => {
            error!("tcp_sendmsg program not found");
            return Ok(());
        }
    };

    if let Err(e) = program_send.load() {
        error!("Failed to load tcp_sendmsg program: {}", e);
        return Ok(());
    }
    if let Err(e) = program_send.attach("tcp_sendmsg", 0) {
        error!("Failed to attach tcp_sendmsg program: {}", e);
        return Ok(());
    }

    let program_recv: &mut KProbe = match ebpf.program_mut("tcp_recvmsg") {
        Some(prog) => match prog.try_into() {
            Ok(prog) => prog,
            Err(e) => {
                error!("Failed to convert tcp_recvmsg program: {}", e);
                return Ok(());
            }
        },
        None => {
            error!("tcp_recvmsg program not found");
            return Ok(());
        }
    };

    if let Err(e) = program_recv.load() {
        error!("Failed to load tcp_recvmsg program: {}", e);
        return Ok(());
    }
    if let Err(e) = program_recv.attach("tcp_recvmsg", 0) {
        error!("Failed to attach tcp_recvmsg program: {}", e);
        return Ok(());
    }
    
    info!("eBPF programs attached successfully");

    // 初始化 maps
    let mut maps = ebpf.maps_mut();
    let mut traffic_stats_0 = None;
    let mut traffic_stats_1 = None;
    let mut control_map = None;

    for (name, map) in maps {
        match name {
            "traffic_stats_0" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, TrafficStats>::try_from(map) {
                    Ok(map) => traffic_stats_0 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_stats_0 map: {}", e);
                        return Ok(());
                    }
                }
            }
            "traffic_stats_1" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfo, TrafficStats>::try_from(map) {
                    Ok(map) => traffic_stats_1 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_stats_1 map: {}", e);
                        return Ok(());
                    }
                }
            }
            "control_map" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, u32, u32>::try_from(map) {
                    Ok(map) => control_map = Some(map),
                    Err(e) => {
                        error!("Failed to convert control_map: {}", e);
                        return Ok(());
                    }
                }
            }
            _ => {}
        }
    }

    let mut traffic_stats_0: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, TrafficStats> = 
        match traffic_stats_0 {
            Some(map) => map,
            None => {
                error!("traffic_stats_0 map not found");
                return Ok(());
            }
        };

    let mut traffic_stats_1: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfo, TrafficStats> = 
        match traffic_stats_1 {
            Some(map) => map,
            None => {
                error!("traffic_stats_1 map not found");
                return Ok(());
            }
        };

    let mut control_map: aya::maps::HashMap<&mut aya::maps::MapData, u32, u32> = 
        match control_map {
            Some(map) => map,
            None => {
                error!("control_map not found");
                return Ok(());
            }
        };

    info!("Maps initialized successfully");
    println!("Starting traffic monitoring...");

    let mut current_buffer = 0;
    let mut current_minute: Option<DateTime<Local>> = None;
    let mut current_data = Vec::new();

    // 主循环
    loop {
        // 获取当前时间并向下取整到统计周期
        let now = Local::now();
        let now_seconds = now.second() as u64;
        let rounded_seconds = (now_seconds / stats_duration) * stats_duration;
        let now = now.with_second(rounded_seconds as u32).unwrap().with_nanosecond(0).unwrap();
        
        debug!("Current time: {}, Rounded time: {}", 
            Local::now().format("%Y-%m-%d %H:%M:%S"),
            now.format("%Y-%m-%d %H:%M:%S")
        );
        
        // 如果是新的统计周期，处理上一周期的数据
        if let Some(last_time) = current_minute {
            if last_time != now {
                debug!("Processing data for previous period: {}", 
                    last_time.format("%Y-%m-%d %H:%M:%S")
                );
                if !current_data.is_empty() {
                    process_traffic_data(last_time, &current_data);
                }
                current_data.clear();
            }
        }
        
        // 更新当前时间
        current_minute = Some(now);
        
        // 切换缓冲区
        current_buffer = 1 - current_buffer;
        debug!("Switching to buffer {}", current_buffer);
        
        // 更新控制映射
        if let Err(e) = control_map.insert(&0, &current_buffer, 0) {
            error!("Failed to update control map: {}", e);
            continue;
        }
        debug!("Control map updated with buffer index: {}", current_buffer);
        
        // 收集非活跃缓冲区的数据
        let inactive_buffer = 1 - current_buffer;
        let map = if inactive_buffer == 0 {
            &mut traffic_stats_0
        } else {
            &mut traffic_stats_1
        };
        
        debug!("Using active buffer: {}, clearing buffer: {}", current_buffer, inactive_buffer);
        
        // 收集数据
        let mut entries_to_remove = Vec::new();
        let mut collected_count = 0;
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        
        for entry in map.iter() {
            match entry {
                Ok((process_info, stats)) => {
                    current_data.push((process_info.clone(), stats.clone()));
                    entries_to_remove.push(process_info.clone());
                    collected_count += 1;
                    total_bytes_sent += stats.bytes_sent;
                    total_bytes_received += stats.bytes_received;

                    // 打印每条收集到的数据
                    let cgroup_name = get_cgroup_name(process_info.cgroup_id);
                    let process_name = get_process_name(&process_info.comm);
                    debug!("Collected entry: cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}, sent={}, received={}",
                        cgroup_name,
                        process_info.pid,
                        process_name,
                        format_ip(process_info.src_ip),
                        format_ip(process_info.dst_ip),
                        stats.bytes_sent,
                        stats.bytes_received
                    );
                }
                Err(e) => {
                    error!("Error reading traffic stats map entry: {:?}", e);
                    continue;
                }
            }
        }
        
        // 打印收集统计
        debug!("Period {}: Collected {} entries from buffer {} (Total: sent={}, received={})", 
            now.format("%Y-%m-%d %H:%M:%S"),
            collected_count,
            inactive_buffer,
            total_bytes_sent,
            total_bytes_received
        );
        
        // 清零非活跃缓冲区
        let mut cleared_count = 0;
        for process_info in entries_to_remove {
            if let Err(e) = map.remove(&process_info) {
                error!("Failed to clear entry from buffer {}: {}", inactive_buffer, e);
            } else {
                cleared_count += 1;
            }
        }
        debug!("Period {}: Cleared {} entries from buffer {}", 
            now.format("%Y-%m-%d %H:%M:%S"),
            cleared_count,
            inactive_buffer
        );

        // 计算下一个统计周期的时间
        let next_period = now + chrono::Duration::seconds(stats_duration as i64);
        let wait_duration = (next_period - Local::now()).num_milliseconds() as u64;
        debug!("Waiting {} ms until next period at {}", 
            wait_duration,
            next_period.format("%Y-%m-%d %H:%M:%S")
        );
        
        // 确保等待时间不超过统计周期，且不小于0
        let wait_duration = std::cmp::min(
            std::cmp::max(wait_duration, 0),
            stats_duration * 1000
        );
        
        if wait_duration > 0 {
            std::thread::sleep(Duration::from_millis(wait_duration));
        }

        // 立即处理当前周期的数据
        if !current_data.is_empty() {
            process_traffic_data(now, &current_data);
            current_data.clear();
        }
    }
}

/// 处理流量数据
fn process_traffic_data(timestamp: DateTime<Local>, data: &[(ProcessInfo, TrafficStats)]) {
    debug!("Processing traffic data for period: {}", timestamp.format("%Y-%m-%d %H:%M:%S"));
    let start_time = Instant::now();
    let mut total_sent: u64 = 0;
    let mut total_received: u64 = 0;
    let mut unique_processes = std::collections::HashSet::new();
    let mut entry_count = 0;

    // 获取命令行参数
    let args = Args::parse();

    // 加载规则
    let rules = match load_rules(&args.rules_file) {
        Ok(rules) => {
            debug!("Loaded {} rules from {}", rules.len(), args.rules_file);
            for (i, rule) in rules.iter().enumerate() {
                debug!("Rule {}: cgroup='{}', process='{}', blacklist_ips={:?}", 
                    i, rule.cgroup, rule.process, rule.blacklist_ips);
            }
            rules
        },
        Err(e) => {
            error!("Failed to load rules from {}: {}", args.rules_file, e);
            return;
        }
    };

    // 创建输出文件
    let output_file = format!("{}/traffic_stats_{}.prom", 
        args.log_dir,
        timestamp.format("%Y%m%d_%H%M%S")
    );
    let file = match File::create(&output_file) {
        Ok(file) => file,
        Err(e) => {
            error!("Failed to create output file {}: {}", output_file, e);
            return;
        }
    };
    let mut writer = BufWriter::new(file);

    // 处理当前周期的所有数据
    for (process_info, stats) in data {
        entry_count += 1;
        unique_processes.insert(process_info.clone());
        
        let (src, dst) = if stats.src_ip <= stats.dst_ip {
            (stats.src_ip as u32, stats.dst_ip as u32)
        } else {
            (stats.dst_ip as u32, stats.src_ip as u32)
        };
        
        // 获取进程名和cgroup名
        let process_name = get_process_name(&process_info.comm);
        let cgroup_name = get_cgroup_name(process_info.cgroup_id);

        // 检查是否匹配任何规则
        let mut matched = false;
        let mut blacklisted = false;

        for rule in &rules {
            if is_process_matched(&process_name, &cgroup_name, rule) {
                matched = true;
                // 检查IP是否在黑名单中
                if is_ip_blacklisted(src, &rule.blacklist_ips) || 
                   is_ip_blacklisted(dst, &rule.blacklist_ips) {
                    blacklisted = true;
                    debug!("Traffic blacklisted: process={}, cgroup={}, src={}, dst={}",
                        process_name, cgroup_name, format_ip(src), format_ip(dst));
                    break;
                }
            }
        }

        // 只处理匹配规则且不在黑名单中的数据
        if matched && !blacklisted {
            // 写入发送流量
            if stats.bytes_sent > 0 {
                debug!("Writing sent traffic - cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}, bytes={}",
                    cgroup_name, process_info.pid, process_name, format_ip(src), format_ip(dst), stats.bytes_sent);
                if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",pid=\"{}\",process=\"{}\",src_ip=\"{}\",dst_ip=\"{}\",direction=\"sent\"}} {}",
                    cgroup_name,
                    process_info.pid,
                    process_name,
                    format_ip(src),
                    format_ip(dst),
                    stats.bytes_sent
                ) {
                    error!("Failed to write sent traffic data: {}", e);
                }
                total_sent += stats.bytes_sent;
            }

            // 写入接收流量
            if stats.bytes_received > 0 {
                debug!("Writing received traffic - cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}, bytes={}",
                    cgroup_name, process_info.pid, process_name, format_ip(dst), format_ip(src), stats.bytes_received);
                if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",pid=\"{}\",process=\"{}\",src_ip=\"{}\",dst_ip=\"{}\",direction=\"received\"}} {}",
                    cgroup_name,
                    process_info.pid,
                    process_name,
                    format_ip(dst),
                    format_ip(src),
                    stats.bytes_received
                ) {
                    error!("Failed to write received traffic data: {}", e);
                }
                total_received += stats.bytes_received;
            }

            debug!("Traffic accepted: process={}, cgroup={}, src={}, dst={}",
                process_name, cgroup_name, format_ip(src), format_ip(dst));
        } else {
            debug!("Traffic filtered out: process={}, cgroup={}, src={}, dst={}, matched={}, blacklisted={}",
                process_name, cgroup_name, format_ip(src), format_ip(dst), matched, blacklisted);
        }
    }

    // 确保所有数据都写入文件
    if let Err(e) = writer.flush() {
        error!("Failed to flush output file: {}", e);
    }

    // 记录处理时间
    let processing_time = start_time.elapsed();
    if processing_time > Duration::from_millis(1000) {
        warn!("Traffic stats processing took {} ms for {} entries", 
            processing_time.as_millis(), 
            entry_count);
    }

    // 打印统计信息
    let map_size = unique_processes.len();
    info!("Map usage: {}/600000 entries", map_size);
    info!("Traffic stats for {}:", timestamp.format("%Y-%m-%d %H:%M:%S"));
    info!("Output file: {}", output_file);

    info!("\nTotal Traffic --- {}s:", timestamp.format("%Y-%m-%d %H:%M:%S"));
    let period_duration = if timestamp.second() == 0 { 60.0 } else { 10.0 };
    let sent_rate = total_sent as f64 / period_duration;
    let received_rate = total_received as f64 / period_duration;
    let total_rate = (total_sent + total_received) as f64 / period_duration;

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
}

