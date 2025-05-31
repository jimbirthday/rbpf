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

/// 流量收集器配置
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 过滤规则文件路径
    #[arg(short, long, default_value = "rules.json")]
    rules: String,

    /// 日志文件目录
    #[arg(short = 'l', long, default_value = "/var/log/mx-cIndicator")]
    log_dir: String,

    /// 日志保留天数（0表示不清理）
    #[arg(short = 'd', long, default_value = "7")]
    log_retention_days: u64,

    /// 日志级别 (debug, info, warn, error)
    #[arg(short = 'v', long, default_value = "info")]
    log_level: String,
}

// 通配符匹配函数
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();
    let mut pattern_idx = 0;
    let mut text_idx = 0;
    let mut star_idx = -1;
    let mut match_idx = 0;

    while text_idx < text_chars.len() {
        if pattern_idx < pattern_chars.len() && 
           (pattern_chars[pattern_idx] == '?' || pattern_chars[pattern_idx] == text_chars[text_idx]) {
            pattern_idx += 1;
            text_idx += 1;
        } else if pattern_idx < pattern_chars.len() && pattern_chars[pattern_idx] == '*' {
            star_idx = pattern_idx as i32;
            match_idx = text_idx;
            pattern_idx += 1;
        } else if star_idx != -1 {
            pattern_idx = (star_idx + 1) as usize;
            match_idx += 1;
            text_idx = match_idx;
        } else {
            return false;
        }
    }

    // 处理模式末尾的星号
    while pattern_idx < pattern_chars.len() && pattern_chars[pattern_idx] == '*' {
        pattern_idx += 1;
    }

    // 如果模式已经匹配完，或者只剩下星号，则匹配成功
    pattern_idx == pattern_chars.len()
}

// 过滤规则结构
#[derive(Debug, Clone)]
struct FilterRule {
    cgroup_pattern: Option<String>,
    pid_pattern: Option<String>,
    process_pattern: Option<String>,
    src_ip_pattern: Option<String>,
    dst_ip_pattern: Option<String>,
}

impl FilterRule {
    // 检查进程是否匹配规则（白名单）
    fn matches_process(&self, process_info: &ProcessInfo) -> bool {
        // 检查 cgroup
        let cgroup_match = self.cgroup_pattern.as_ref().map_or(true, |pattern| {
            let cgroup_name = get_cgroup_name(process_info.cgroup_id);
            wildcard_match(pattern, &cgroup_name)
        });
        
        // 检查进程名
        let process_match = self.process_pattern.as_ref().map_or(true, |pattern| {
            let process_name = get_process_name(&process_info.comm);
            wildcard_match(pattern, &process_name)
        });
        
        // 进程规则只需要匹配进程相关的条件
        cgroup_match && process_match
    }

    // 检查IP是否匹配规则（黑名单）
    fn matches_ip(&self, src_ip: u32, dst_ip: u32) -> bool {
        let src_ip_str = format_ip(src_ip);
        let dst_ip_str = format_ip(dst_ip);
        
        // 如果规则中有IP相关的模式，检查是否匹配
        let src_match = self.src_ip_pattern.as_ref().map_or(false, |pattern| 
            wildcard_match(pattern, &src_ip_str));
        let dst_match = self.dst_ip_pattern.as_ref().map_or(false, |pattern| 
            wildcard_match(pattern, &dst_ip_str));
        
        // IP规则只需要匹配IP相关的条件
        src_match || dst_match
    }
}

// 检查进程是否应该被包含（白名单）
fn should_include_process(process_info: &ProcessInfo, filter_rules: &[FilterRule]) -> bool {
    if filter_rules.is_empty() {
        true // 如果没有规则，包含所有流量
    } else {
        filter_rules.iter().any(|rule| rule.matches_process(process_info))
    }
}

// 检查IP是否应该被排除（黑名单）
fn should_exclude_ip(src_ip: u32, dst_ip: u32, filter_rules: &[FilterRule]) -> bool {
    if filter_rules.is_empty() {
        false // 如果没有规则，不排除任何IP
    } else {
        filter_rules.iter().any(|rule| rule.matches_ip(src_ip, dst_ip))
    }
}

// 加载过滤规则
fn load_filter_rules(file_path: &str) -> anyhow::Result<Vec<FilterRule>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let json: Value = serde_json::from_reader(reader)?;
    
    let mut rules = Vec::new();
    
    // 确保根节点是数组
    if let Value::Array(rules_array) = json {
        for rule_value in rules_array {
            if let Value::Object(rule_obj) = rule_value {
                let mut rule = FilterRule {
                    cgroup_pattern: None,
                    pid_pattern: None,
                    process_pattern: None,
                    src_ip_pattern: None,
                    dst_ip_pattern: None,
                };
                
                // 解析规则字段
                if let Some(Value::String(pattern)) = rule_obj.get("cgroup") {
                    rule.cgroup_pattern = Some(pattern.clone());
                }
                if let Some(Value::String(pattern)) = rule_obj.get("pid") {
                    rule.pid_pattern = Some(pattern.clone());
                }
                if let Some(Value::String(pattern)) = rule_obj.get("process") {
                    rule.process_pattern = Some(pattern.clone());
                }
                if let Some(Value::String(pattern)) = rule_obj.get("src_ip") {
                    rule.src_ip_pattern = Some(pattern.clone());
                }
                if let Some(Value::String(pattern)) = rule_obj.get("dst_ip") {
                    rule.dst_ip_pattern = Some(pattern.clone());
                }
                
                rules.push(rule);
            }
        }
    } else {
        return Err(anyhow::anyhow!("Filter rules must be an array"));
    }
    
    Ok(rules)
}

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

// 写入统计信息到文件
fn write_stats_to_file(
    traffic_stats: &HashMap<ProcessInfo, TrafficStats>,
    timestamp: DateTime<Local>,
    filter_rules: &[FilterRule],
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

    // 按进程和IP对聚合流量统计
    let mut traffic_agg: HashMap<(ProcessInfo, u32, u32), (u64, u64)> = HashMap::new();
    let mut debug_total_sent: u64 = 0;
    let mut debug_total_received: u64 = 0;

    // 遍历所有流量记录
    for (process_info, stats) in traffic_stats.iter() {
        // 确保源IP和目标IP的顺序一致（较小的IP作为源IP）
        let (src, dst) = if stats.src_ip <= stats.dst_ip {
            (stats.src_ip as u32, stats.dst_ip as u32)
        } else {
            (stats.dst_ip as u32, stats.src_ip as u32)
        };

        // 如果不应该排除这个IP，则包含它
        if !should_exclude_ip(src, dst, filter_rules) {
            // 更新聚合统计
            let key = (*process_info, src, dst);
            let entry = traffic_agg.entry(key).or_insert((0, 0));
            
            // 根据方向更新发送和接收的字节数
            if stats.direction == 0 {
                entry.0 += stats.bytes_sent;
                debug_total_sent += stats.bytes_sent;
            } else {
                entry.1 += stats.bytes_received;
                debug_total_received += stats.bytes_received;
            }
        }
    }

    debug!("Aggregated traffic - Total sent: {}, Total received: {}", debug_total_sent, debug_total_received);

    // 写入聚合后的流量统计
    for ((process_info, src_ip, dst_ip), (sent, received)) in traffic_agg.iter() {
        let cgroup_name = get_cgroup_name(process_info.cgroup_id);
        let process_name = get_process_name(&process_info.comm);
        
        // 写入发送流量
        if *sent > 0 {
            debug!("Writing sent traffic - cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}, bytes={}",
                cgroup_name, process_info.pid, process_name, format_ip(*src_ip), format_ip(*dst_ip), sent);
            writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",pid=\"{}\",process=\"{}\",src_ip=\"{}\",dst_ip=\"{}\"}} {}",
                cgroup_name,
                process_info.pid,
                process_name,
                format_ip(*src_ip),
                format_ip(*dst_ip),
                sent
            )?;
        }
        
        // 写入接收流量
        if *received > 0 {
            debug!("Writing received traffic - cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}, bytes={}",
                cgroup_name, process_info.pid, process_name, format_ip(*dst_ip), format_ip(*src_ip), received);
            writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",pid=\"{}\",process=\"{}\",src_ip=\"{}\",dst_ip=\"{}\"}} {}",
                cgroup_name,
                process_info.pid,
                process_name,
                format_ip(*dst_ip),
                format_ip(*src_ip),
                received
            )?;
        }
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

// 添加日志清理函数
fn cleanup_old_logs(log_dir: &str, retention_days: u64) -> anyhow::Result<()> {
    let log_path = Path::new(log_dir);
    if !log_path.exists() {
        return Ok(());
    }

    let now = Local::now();
    let retention_duration = chrono::Duration::days(retention_days as i64);

    for entry in fs::read_dir(log_path)? {
        let entry = entry?;
        let path = entry.path();
        
        if path.is_file() && path.extension().map_or(false, |ext| ext == "prom") {
            if let Ok(metadata) = fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    let modified: DateTime<Local> = modified.into();
                    if now.signed_duration_since(modified) > retention_duration {
                        fs::remove_file(path)?;
                        info!("Removed old log file: {}", entry.file_name().to_string_lossy());
                    }
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 解析命令行参数
    let args = Args::parse();

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
        });

    // 根据命令行参数设置日志级别
    let log_level = match args.log_level.to_lowercase().as_str() {
        "debug" => log::LevelFilter::Debug,
        "info" => log::LevelFilter::Info,
        "warn" => log::LevelFilter::Warn,
        "error" => log::LevelFilter::Error,
        _ => {
            eprintln!("Invalid log level: {}. Using default level: info", args.log_level);
            log::LevelFilter::Info
        }
    };
    builder.filter(None, log_level).init();

    info!("Starting traffic collector...");
    info!("Using configuration:");
    info!("  Rules file: {}", args.rules);
    info!("  Log directory: {}", args.log_dir);
    if args.log_retention_days > 0 {
        info!("  Log retention: {} days", args.log_retention_days);
    } else {
        info!("  Log retention: disabled");
    }
    info!("  Log level: {}", args.log_level);

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
        let mut last_cleanup_time = Local::now();
        
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
            
            // 检查是否需要清理日志（每小时检查一次）
            if args.log_retention_days > 0 && (current_time - last_cleanup_time).num_hours() >= 1 {
                if let Err(e) = cleanup_old_logs(&args.log_dir, args.log_retention_days) {
                    error!("Failed to cleanup old logs: {}", e);
                }
                last_cleanup_time = current_time;
            }
            
            // 只有当距离上次打印超过1分钟时才打印统计信息
            if (current_time - last_print_time).num_seconds() >= 60 {
                // 执行清理
                if let Err(e) = cleanup_inactive_entries(&mut traffic_stats_map) {
                    error!("Failed to cleanup inactive entries: {}", e);
                }
                
                // 加载过滤规则
                let filter_rules = match load_filter_rules(&args.rules) {
                    Ok(rules) => {
                        info!("Loaded {} filter rules:", rules.len());
                        for (i, rule) in rules.iter().enumerate() {
                            info!("Rule {}:", i + 1);
                            if let Some(pattern) = &rule.cgroup_pattern {
                                info!("  CGroup pattern: {}", pattern);
                            }
                            if let Some(pattern) = &rule.pid_pattern {
                                info!("  PID pattern: {}", pattern);
                            }
                            if let Some(pattern) = &rule.process_pattern {
                                info!("  Process pattern: {}", pattern);
                            }
                            if let Some(pattern) = &rule.src_ip_pattern {
                                info!("  Source IP pattern: {}", pattern);
                            }
                            if let Some(pattern) = &rule.dst_ip_pattern {
                                info!("  Destination IP pattern: {}", pattern);
                            }
                        }
                        rules
                    }
                    Err(e) => {
                        warn!("Failed to load filter rules: {}", e);
                        Vec::new()
                    }
                };
                
                // 在主循环中修改统计逻辑
                let mut traffic_stats: HashMap<ProcessInfo, TrafficStats> = HashMap::new();
                let mut total_sent: u64 = 0;
                let mut total_received: u64 = 0;
                let mut unique_processes: std::collections::HashSet<ProcessInfo> = std::collections::HashSet::new();
                
                // 获取所有当前有流量的进程数据
                for entry in traffic_stats_map.iter() {
                    match entry {
                        Ok((process_info, stats)) => {
                            unique_processes.insert(process_info.clone());
                            
                            // 应用进程过滤规则（白名单）
                            if should_include_process(&process_info, &filter_rules) {
                                // 确保源IP和目标IP的顺序一致（较小的IP作为源IP）
                                let (src, dst) = if stats.src_ip <= stats.dst_ip {
                                    (stats.src_ip as u32, stats.dst_ip as u32)
                                } else {
                                    (stats.dst_ip as u32, stats.src_ip as u32)
                                };
                                
                                // 如果不应该排除这个IP，则包含它
                                if !should_exclude_ip(src, dst, &filter_rules) {
                                    // 更新流量统计
                                    let mut current_stats = stats.clone();
                                    
                                    // 根据方向更新发送和接收的字节数
                                    if stats.direction == 0 {
                                        current_stats.bytes_sent = stats.bytes_sent;
                                        current_stats.bytes_received = 0;
                                        total_sent += stats.bytes_sent;
                                    } else {
                                        current_stats.bytes_sent = 0;
                                        current_stats.bytes_received = stats.bytes_received;
                                        total_received += stats.bytes_received;
                                    }
                                    
                                    // 使用进程信息和IP对作为键
                                    let mut key_process_info = process_info.clone();
                                    key_process_info.src_ip = src;
                                    key_process_info.dst_ip = dst;
                                    
                                    // 更新或插入统计信息
                                    traffic_stats.insert(key_process_info, current_stats);
                                    
                                    debug!("Raw traffic data - cgroup={}, pid={}, process={}, src_ip={}, dst_ip={}: sent={}, received={}, direction={}", 
                                        process_info.cgroup_id, 
                                        process_info.pid,
                                        get_process_name(&process_info.comm),
                                        format_ip(src),
                                        format_ip(dst),
                                        current_stats.bytes_sent,
                                        current_stats.bytes_received,
                                        stats.direction);
                                }
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
                    &traffic_stats,
                    current_time,
                    &filter_rules,
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
                debug!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15} {:<15} {:<15}", 
                    "CGroup", "PID", "Process", "Source IP", "Dest IP", "Bytes Sent", "Bytes Received", "Total");
                
                if traffic_stats.is_empty() {
                    debug!("No traffic detected in the last minute");
                } else {
                    for (process_info, stats) in traffic_stats.iter() {
                        let cgroup_name = get_cgroup_name(process_info.cgroup_id);
                        let process_name = get_process_name(&process_info.comm);
                        let total = stats.bytes_sent + stats.bytes_received;
                        
                        debug!("{:<20} {:<8} {:<20} {:<15} {:<15} {:<15} {:<15} {:<15}", 
                            cgroup_name,
                            process_info.pid,
                            process_name,
                            format_ip(stats.src_ip as u32),
                            format_ip(stats.dst_ip as u32),
                            stats.bytes_sent,
                            stats.bytes_received,
                            total);
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

