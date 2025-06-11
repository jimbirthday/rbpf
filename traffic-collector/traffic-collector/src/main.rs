use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, warn, info, error, trace};
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
use std::collections::HashSet;

/// 流量收集器配置
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Statistics duration in seconds
    #[arg(short = 't', long, default_value = "60")]
    duration: u64,

    /// Rules file path
    #[arg(short = 'r', long, default_value = "rules.json")]
    rules_file: String,

    /// Log level (info, debug, trace)
    #[arg(short = 'L', long, default_value = "debug")]
    log_level: String,

    /// Log directory
    #[arg(short = 'd', long, default_value = "/var/log/mx-cIndicator")]
    log_dir: String,

    /// Verbose level (0: Info, 1: Debug, 2: Trace)
    #[arg(short = 'v', long, default_value = "0")]
    verbose: u8,
}

// 定义最小流量阈值（字节）
const MIN_TRAFFIC_THRESHOLD: u64 = 1024; // 1KB

// 定义进程信息结构，需要与 eBPF 程序中的结构体匹配
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessInfoKey {
    pub cgroup_id: u64,    // 8 bytes
    pub pid: u32,          // 4 bytes
    pub comm: [u8; 8],     // 8 bytes - 存储进程名的前8个字符
    _pad: [u8; 4],         // 4 bytes padding to ensure 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStatsHeader {
    pub bytes_sent: u64,      // 8 bytes
    pub bytes_received: u64,  // 8 bytes
    pub last_activity: u64,   // 8 bytes
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStatsNetwork {
    pub src_ip: u32,          // 4 bytes
    pub dst_ip: u32,          // 4 bytes
    pub src_port: u16,        // 2 bytes
    pub dst_port: u16,        // 2 bytes
    pub direction: u32,       // 4 bytes
    _pad: [u8; 4],           // 4 bytes padding to ensure 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrafficStats {
    pub header: TrafficStatsHeader,
    pub network: TrafficStatsNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub cgroup_id: u64,    // 8 bytes
    pub src_ip: u32,       // 4 bytes
    pub dst_ip: u32,       // 4 bytes
    pub src_port: u16,     // 2 bytes
    pub dst_port: u16,     // 2 bytes
    _pad: [u8; 4],         // 4 bytes padding to ensure 8-byte alignment
}

// 实现 Pod trait
unsafe impl Pod for ProcessInfoKey {}
unsafe impl Pod for TrafficStatsHeader {}
unsafe impl Pod for TrafficStatsNetwork {}
unsafe impl Pod for TrafficStats {}

// 获取 cgroup 名称的辅助函数
fn get_cgroup_name(cgroup_id: u64) -> String {
    format!("cgroup_{}", cgroup_id)
}

// 修改获取进程名的辅助函数
fn get_process_name(comm: &[u8; 8], pid: u32) -> String {
    // 找到第一个null字节的位置
    let null_pos = comm.iter().position(|&x| x == 0).unwrap_or(comm.len());
    // 将字节切片转换为字符串
    let name = String::from_utf8_lossy(&comm[..null_pos]).to_string();
    if name.is_empty() {
        // 如果进程名为空，尝试从 /proc 获取进程名
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{}/comm", pid)) {
            comm.trim().to_string()
        } else {
            format!("unknown_{}", pid)
        }
    } else {
        name
    }
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
        debug!("Rule matches all: no process or cgroup specified");
        return true;
    }

    // 检查进程名
    let process_matched = if !rule.process.is_empty() {
        if let Ok(pat) = Pattern::new(&rule.process) {
            let matched = pat.matches(process_name);
            debug!("Process name matching: '{}' against pattern '{}' -> {}", 
                process_name, rule.process, matched);
            matched
        } else {
            debug!("Invalid process name pattern: {}", rule.process);
            false
        }
    } else {
        debug!("No process name pattern specified, matching all");
        true
    };

    // 检查cgroup
    let cgroup_matched = if !rule.cgroup.is_empty() {
        if let Ok(pat) = Pattern::new(&rule.cgroup) {
            let matched = pat.matches(cgroup_name);
            debug!("Cgroup matching: '{}' against pattern '{}' -> {}", 
                cgroup_name, rule.cgroup, matched);
            matched
        } else {
            debug!("Invalid cgroup pattern: {}", rule.cgroup);
            false
        }
    } else {
        debug!("No cgroup pattern specified, matching all");
        true
    };

    let result = process_matched && cgroup_matched;
    debug!("Final rule match result: {} (process: {}, cgroup: {})", 
        result, process_matched, cgroup_matched);
    result
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    // 设置日志级别
    let log_level = match args.log_level.to_lowercase().as_str() {
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _ => match args.verbose {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        }
    };

    // 配置日志
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(log_level)
        .format_timestamp_millis()
        .format_module_path(false)
        .format_target(false)
        .format_indent(None)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {}] {}",
                record.level(),
                record.target(),
                record.args()
            )
        });

    // 初始化日志
    builder.init();
    info!("Starting traffic collector with log level: {}", log_level);

    // 设置统计时长
    let stats_duration = if log_level == log::LevelFilter::Debug {
        10 // debug模式下固定10秒
    } else {
        args.duration // 其他模式使用命令行参数指定的时长
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
        Ok(ebpf) => {
            info!("Successfully loaded eBPF program");
            ebpf
        },
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
            Ok(prog) => {
                info!("Successfully converted tcp_sendmsg program");
                prog
            },
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
    info!("Successfully loaded tcp_sendmsg program");

    if let Err(e) = program_send.attach("tcp_sendmsg", 0) {
        error!("Failed to attach tcp_sendmsg program: {}", e);
        return Ok(());
    }
    info!("Successfully attached tcp_sendmsg program");

    let program_recv: &mut KProbe = match ebpf.program_mut("tcp_recvmsg") {
        Some(prog) => match prog.try_into() {
            Ok(prog) => {
                info!("Successfully converted tcp_recvmsg program");
                prog
            },
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
    info!("Successfully loaded tcp_recvmsg program");

    if let Err(e) = program_recv.attach("tcp_recvmsg", 0) {
        error!("Failed to attach tcp_recvmsg program: {}", e);
        return Ok(());
    }
    info!("Successfully attached tcp_recvmsg program");
    
    info!("eBPF programs attached successfully");

    // 初始化 maps
    let mut maps = ebpf.maps_mut();
    let mut traffic_stats_0 = None;
    let mut traffic_stats_1 = None;
    let mut traffic_network_0 = None;
    let mut traffic_network_1 = None;
    let mut control_map = None;

    for (name, map) in maps {
        match name {
            "traffic_stats_0" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsHeader>::try_from(map) {
                    Ok(map) => traffic_stats_0 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_stats_0 map: {}", e);
                        return Ok(());
                    }
                }
            }
            "traffic_stats_1" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsHeader>::try_from(map) {
                    Ok(map) => traffic_stats_1 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_stats_1 map: {}", e);
                        return Ok(());
                    }
                }
            }
            "traffic_network_0" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsNetwork>::try_from(map) {
                    Ok(map) => traffic_network_0 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_network_0 map: {}", e);
                        return Ok(());
                    }
                }
            }
            "traffic_network_1" => {
                match aya::maps::HashMap::<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsNetwork>::try_from(map) {
                    Ok(map) => traffic_network_1 = Some(map),
                    Err(e) => {
                        error!("Failed to convert traffic_network_1 map: {}", e);
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

    let mut traffic_stats_0: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsHeader> = 
        match traffic_stats_0 {
            Some(map) => map,
            None => {
                error!("traffic_stats_0 map not found");
                return Ok(());
            }
        };

    let mut traffic_stats_1: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsHeader> = 
        match traffic_stats_1 {
            Some(map) => map,
            None => {
                error!("traffic_stats_1 map not found");
                return Ok(());
            }
        };

    let mut traffic_network_0: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsNetwork> = 
        match traffic_network_0 {
            Some(map) => map,
            None => {
                error!("traffic_network_0 map not found");
                return Ok(());
            }
        };

    let mut traffic_network_1: aya::maps::HashMap<&mut aya::maps::MapData, ProcessInfoKey, TrafficStatsNetwork> = 
        match traffic_network_1 {
            Some(map) => map,
            None => {
                error!("traffic_network_1 map not found");
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
            (&mut traffic_stats_0, &mut traffic_network_0)
        } else {
            (&mut traffic_stats_1, &mut traffic_network_1)
        };
        
        debug!("Using active buffer: {}, clearing buffer: {}", current_buffer, inactive_buffer);
        
        // 收集数据并按 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 聚合
        let mut entries_to_remove = Vec::new();
        let mut collected_count = 0;
        let mut total_bytes_sent = 0;
        let mut total_bytes_received = 0;
        let mut connection_stats: HashMap<(u64, u32, u32, u16, u16), (TrafficStatsHeader, TrafficStatsNetwork, u32, u32)> = HashMap::new();
        
        // 获取当前活动的 map
        let (stats_map, network_map) = map;
        
        // 打印 map 中的键数量
        let mut key_count = 0;
        for _ in stats_map.keys() {
            key_count += 1;
        }
        debug!("Found {} keys in stats map", key_count);
        
        // 遍历所有键
        for key_result in stats_map.keys() {
            if let Ok(key) = key_result {
                debug!("Processing key: cgroup_id={}, pid={}, comm={}", 
                    key.cgroup_id, key.pid, String::from_utf8_lossy(&key.comm));
                
                if let (Ok(header), Ok(network)) = (stats_map.get(&key, 0), network_map.get(&key, 0)) {
                    debug!("Found data in maps: sent={}, received={}, src={}:{}, dst={}:{}",
                        header.bytes_sent,
                        header.bytes_received,
                        format_ip(network.src_ip),
                        network.src_port,
                        format_ip(network.dst_ip),
                        network.dst_port
                    );
                    
                    // 按 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 聚合流量
                    let conn_key = (key.cgroup_id, network.src_ip, network.dst_ip, 
                                  network.src_port, network.dst_port);
                    let entry = connection_stats.entry(conn_key).or_insert((
                        TrafficStatsHeader {
                            bytes_sent: 0,
                            bytes_received: 0,
                            last_activity: header.last_activity,
                        },
                        TrafficStatsNetwork {
                            src_ip: network.src_ip,
                            dst_ip: network.dst_ip,
                            src_port: network.src_port,
                            dst_port: network.dst_port,
                            direction: network.direction,
                            _pad: [0u8; 4],
                        },
                        key.pid,
                        key.pid,
                    ));
                    
                    // 累加流量
                    entry.0.bytes_sent += header.bytes_sent;
                    entry.0.bytes_received += header.bytes_received;
                    
                    entries_to_remove.push(key.clone());
                    collected_count += 1;
                    total_bytes_sent += header.bytes_sent;
                    total_bytes_received += header.bytes_received;

                    // 打印每条收集到的数据
                    let cgroup_name = get_cgroup_name(key.cgroup_id);
                    debug!("Collected entry: cgroup={}, pid={}, src={}:{}, dst={}:{}, sent={}, received={}",
                        cgroup_name,
                        key.pid,
                        format_ip(network.src_ip),
                        network.src_port,
                        format_ip(network.dst_ip),
                        network.dst_port,
                        header.bytes_sent,
                        header.bytes_received
                    );
                } else {
                    debug!("No data found in maps for key: cgroup_id={}, pid={}, comm={}", 
                        key.cgroup_id, key.pid, String::from_utf8_lossy(&key.comm));
                }
            } else {
                debug!("Failed to get key from map: {:?}", key_result);
            }
        }
        
        // 将聚合后的数据添加到当前周期
        for ((cgroup_id, src_ip, dst_ip, src_port, dst_port), (header, network, pid, comm_hash)) in connection_stats {
            // 创建一个新的 ProcessInfoKey 来存储聚合后的数据
            let process_info = ProcessInfoKey {
                cgroup_id,
                pid,
                comm: [0; 8],
                _pad: [0; 4],
            };
            current_data.push((process_info, TrafficStats { header, network }));
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
            if let Err(e) = stats_map.remove(&process_info) {
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

        // 立即处理当前周期的数据
        if !current_data.is_empty() {
            process_traffic_data(now, &current_data);
            current_data.clear();
        }

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
        
        // 使用更短的等待时间，更频繁地检查数据
        let check_interval = 100; // 每100ms检查一次
        let mut remaining_wait = wait_duration;
        
        while remaining_wait > 0 {
            let sleep_time = std::cmp::min(check_interval, remaining_wait);
            tokio::time::sleep(Duration::from_millis(sleep_time)).await;
            remaining_wait -= sleep_time;
            
            // 检查是否有新数据，但不立即处理
            let current_map = if current_buffer == 0 {
                (&mut traffic_stats_0, &mut traffic_network_0)
            } else {
                (&mut traffic_stats_1, &mut traffic_network_1)
            };
            
            let mut has_new_data = false;
            for key_result in current_map.0.keys() {
                if let Ok(key) = key_result {
                    if let Ok(_) = current_map.0.get(&key, 0) {
                        has_new_data = true;
                        break;
                    }
                }
            }

        }
    }
}

/// 处理流量数据
fn process_traffic_data(timestamp: DateTime<Local>, data: &[(ProcessInfoKey, TrafficStats)]) {
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

    // 使用 HashMap 来聚合 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 的流量
    let mut aggregated_traffic: HashMap<(u64, u32, u32, u16, u16), (String, String, u64, u64)> = HashMap::new();
    let mut raw_traffic_count = 0;
    let mut aggregated_count = 0;

    // 处理当前周期的所有数据
    for (process_info, stats) in data {
        entry_count += 1;
        unique_processes.insert(process_info.clone());
        raw_traffic_count += 1;
        
        // 获取进程名和cgroup名
        let process_name = get_process_name(&process_info.comm, process_info.pid);
        let cgroup_name = get_cgroup_name(process_info.cgroup_id);

        // 添加调试信息
        debug!("Processing traffic - pid: {}, process: {}, cgroup: {}, src: {}:{}, dst: {}:{}, sent: {}, received: {}", 
            process_info.pid,
            process_name,
            cgroup_name,
            format_ip(stats.network.src_ip),
            stats.network.src_port,
            format_ip(stats.network.dst_ip),
            stats.network.dst_port,
            stats.header.bytes_sent,
            stats.header.bytes_received
        );

        // 检查是否匹配任何规则
        let mut matched = false;
        let mut blacklisted = false;

        for rule in &rules {
            if is_process_matched(&process_name, &cgroup_name, rule) {
                matched = true;
                debug!("Traffic matched rule: cgroup='{}', process='{}', blacklist_ips={:?}", 
                    rule.cgroup, rule.process, rule.blacklist_ips);
                
                // 检查IP是否在黑名单中
                if is_ip_blacklisted(stats.network.src_ip, &rule.blacklist_ips) || 
                   is_ip_blacklisted(stats.network.dst_ip, &rule.blacklist_ips) {
                    blacklisted = true;
                    debug!("Traffic blacklisted: process={}, cgroup={}, src={}:{}, dst={}:{}",
                        process_name, cgroup_name, 
                        format_ip(stats.network.src_ip), stats.network.src_port,
                        format_ip(stats.network.dst_ip), stats.network.dst_port);
                    break;
                }
            }
        }

        // 只处理匹配规则且不在黑名单中的数据
        if matched && !blacklisted {
            // 聚合 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 的流量
            let key = (process_info.cgroup_id, stats.network.src_ip, stats.network.dst_ip, 
                      stats.network.src_port, stats.network.dst_port);
            let entry = aggregated_traffic.entry(key).or_insert((
                cgroup_name.clone(),
                process_name.clone(),
                0,
                0
            ));
            
            // 累加流量
            entry.2 += stats.header.bytes_sent;
            entry.3 += stats.header.bytes_received;
            aggregated_count += 1;

            debug!("Aggregating traffic for cgroup={}, pid={}, src={}:{}, dst={}:{}: sent={}, received={}",
                process_info.cgroup_id, 
                process_info.pid,
                format_ip(stats.network.src_ip), stats.network.src_port,
                format_ip(stats.network.dst_ip), stats.network.dst_port,
                stats.header.bytes_sent, stats.header.bytes_received);
        }
    }

    // 在debug模式下输出聚合后的数据
    debug!("Traffic aggregation summary:");
    debug!("Raw traffic entries: {}", raw_traffic_count);
    debug!("Aggregated entries: {}", aggregated_count);
    debug!("Aggregation ratio: {:.2}%", (aggregated_count as f64 / raw_traffic_count as f64) * 100.0);

    // 写入聚合后的流量数据
    for ((cgroup_id, src_ip, dst_ip, src_port, dst_port), (cgroup_name, process_name, sent, received)) in aggregated_traffic {
        // 在debug模式下输出聚合后的详细数据
        trace!("Aggregated traffic: cgroup={}, src={}:{}, dst={}:{}, process={}, cgroup={}, sent={}, received={}",
            cgroup_id, 
            format_ip(src_ip), src_port,
            format_ip(dst_ip), dst_port,
            process_name, cgroup_name, sent, received);

        // 只处理超过阈值的流量
        if sent >= MIN_TRAFFIC_THRESHOLD {
            debug!("Writing sent traffic - cgroup={}, src={}:{}, dst={}:{}, process={}, bytes={}",
                cgroup_name, 
                format_ip(src_ip), src_port,
                format_ip(dst_ip), dst_port,
                process_name, sent);
            if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",src=\"{}\",dst=\"{}\",process=\"{}\",direction=\"sent\"}} {}",
                cgroup_name,
                format!("{}:{}", format_ip(src_ip), src_port),
                format!("{}:{}", format_ip(dst_ip), dst_port),
                process_name,
                sent
            ) {
                error!("Failed to write sent traffic data: {}", e);
            }
            total_sent += sent;
        }

        if received >= MIN_TRAFFIC_THRESHOLD {
            debug!("Writing received traffic - cgroup={}, src={}:{}, dst={}:{}, process={}, bytes={}",
                cgroup_name, 
                format_ip(src_ip), src_port,
                format_ip(dst_ip), dst_port,
                process_name, received);
            if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",src=\"{}\",dst=\"{}\",process=\"{}\",direction=\"received\"}} {}",
                cgroup_name,
                format!("{}:{}", format_ip(src_ip), src_port),
                format!("{}:{}", format_ip(dst_ip), dst_port),
                process_name,
                received
            ) {
                error!("Failed to write received traffic data: {}", e);
            }
            total_received += received;
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

fn process_traffic_stats(
    data: Vec<(ProcessInfoKey, TrafficStats)>,
    rules: &[Rule],
    writer: &mut BufWriter<File>,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let mut total_sent = 0u64;
    let mut total_received = 0u64;
    let mut entry_count = 0u64;
    let mut unique_processes = HashSet::new();

    debug!("Processing {} traffic entries", data.len());

    // 使用 HashMap 来聚合 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 的流量
    let mut aggregated_traffic: HashMap<(u64, u32, u32, u16, u16), (String, String, u64, u64)> = HashMap::new();
    let mut raw_traffic_count = 0;
    let mut aggregated_count = 0;

    // 处理当前周期的所有数据
    for (process_info, stats) in data {
        entry_count += 1;
        unique_processes.insert(process_info.clone());
        raw_traffic_count += 1;
        
        // 获取进程名和cgroup名
        let process_name = get_process_name(&process_info.comm, process_info.pid);
        let cgroup_name = get_cgroup_name(process_info.cgroup_id);

        // 在debug模式下输出原始数据
        debug!("Raw traffic data: pid={}, process={}, cgroup={}, src={}:{}, dst={}:{}, sent={}, received={}",
            process_info.pid,
            process_name,
            cgroup_name,
            format_ip(stats.network.src_ip),
            stats.network.src_port,
            format_ip(stats.network.dst_ip),
            stats.network.dst_port,
            stats.header.bytes_sent,
            stats.header.bytes_received
        );

        // 检查是否匹配任何规则
        let mut matched = false;
        let mut blacklisted = false;

        for rule in rules {
            if is_process_matched(&process_name, &cgroup_name, rule) {
                matched = true;
                // 检查IP是否在黑名单中
                if is_ip_blacklisted(stats.network.src_ip, &rule.blacklist_ips) || 
                   is_ip_blacklisted(stats.network.dst_ip, &rule.blacklist_ips) {
                    blacklisted = true;
                    debug!("Traffic blacklisted: process={}, cgroup={}, src={}:{}, dst={}:{}",
                        process_name, cgroup_name, 
                        format_ip(stats.network.src_ip), stats.network.src_port,
                        format_ip(stats.network.dst_ip), stats.network.dst_port);
                    break;
                }
            }
        }

        // 只处理匹配规则且不在黑名单中的数据
        if matched && !blacklisted {
            // 聚合 (cgroup_id, src_ip, dst_ip, src_port, dst_port) 的流量
            let key = (process_info.cgroup_id, stats.network.src_ip, stats.network.dst_ip, 
                      stats.network.src_port, stats.network.dst_port);
            let entry = aggregated_traffic.entry(key).or_insert((
                cgroup_name.clone(),
                process_name.clone(),
                0,
                0
            ));
            
            // 累加流量
            entry.2 += stats.header.bytes_sent;
            entry.3 += stats.header.bytes_received;
            aggregated_count += 1;

            debug!("Aggregating traffic for cgroup={}, pid={}, src={}:{}, dst={}:{}: sent={}, received={}",
                process_info.cgroup_id, 
                process_info.pid,
                format_ip(stats.network.src_ip), stats.network.src_port,
                format_ip(stats.network.dst_ip), stats.network.dst_port,
                stats.header.bytes_sent, stats.header.bytes_received);
        }
    }

    // 在debug模式下输出聚合后的数据
    debug!("Traffic aggregation summary:");
    debug!("Raw traffic entries: {}", raw_traffic_count);
    debug!("Aggregated entries: {}", aggregated_count);
    debug!("Aggregation ratio: {:.2}%", (aggregated_count as f64 / raw_traffic_count as f64) * 100.0);

    // 写入聚合后的流量数据
    for ((cgroup_id, src_ip, dst_ip, src_port, dst_port), (cgroup_name, process_name, sent, received)) in aggregated_traffic {
        // 在debug模式下输出聚合后的详细数据
        debug!("Aggregated traffic: cgroup={}, src={}:{}, dst={}:{}, process={}, cgroup={}, sent={}, received={}",
            cgroup_id, 
            format_ip(src_ip), src_port,
            format_ip(dst_ip), dst_port,
            process_name, cgroup_name, sent, received);

        // 只处理超过阈值的流量
        if sent >= MIN_TRAFFIC_THRESHOLD {
            debug!("Writing sent traffic - cgroup={}, src={}:{}, dst={}:{}, process={}, bytes={}",
                cgroup_name, 
                format_ip(src_ip), src_port,
                format_ip(dst_ip), dst_port,
                process_name, sent);
            if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",src=\"{}\",dst=\"{}\",process=\"{}\",direction=\"sent\"}} {}",
                cgroup_name,
                format!("{}:{}", format_ip(src_ip), src_port),
                format!("{}:{}", format_ip(dst_ip), dst_port),
                process_name,
                sent
            ) {
                error!("Failed to write sent traffic data: {}", e);
            }
            total_sent += sent;
        }

        if received >= MIN_TRAFFIC_THRESHOLD {
            debug!("Writing received traffic - cgroup={}, src={}:{}, dst={}:{}, process={}, bytes={}",
                cgroup_name, 
                format_ip(src_ip), src_port,
                format_ip(dst_ip), dst_port,
                process_name, received);
            if let Err(e) = writeln!(writer, "ebpf_traffic_stats{{cgroup=\"{}\",src=\"{}\",dst=\"{}\",process=\"{}\",direction=\"received\"}} {}",
                cgroup_name,
                format!("{}:{}", format_ip(src_ip), src_port),
                format!("{}:{}", format_ip(dst_ip), dst_port),
                process_name,
                received
            ) {
                error!("Failed to write received traffic data: {}", e);
            }
            total_received += received;
        }
    }

    Ok((total_sent, total_received))
}

