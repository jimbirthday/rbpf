use aya::programs::KProbe;
#[rustfmt::skip]
use log::{debug, warn, info, error};
use tokio::signal;
use tokio::time::{self, Duration};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::collections::HashMap;
use std::process::Command;

// 全局计数器
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 设置日志级别为 debug 以获取更多信息
    std::env::set_var("RUST_LOG", "debug");
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

    // 创建共享计数器
    let bytes_sent = Arc::new(AtomicU64::new(0));

    println!("Starting eBPF monitoring...");
    // 启动 eBPF 任务
    let ebpf_handle = tokio::spawn(async move {
        // 获取并加载程序
        let program: &mut KProbe = ebpf.program_mut("traffic_collector").unwrap().try_into().unwrap();
        program.load().unwrap();
        program.attach("tcp_sendmsg", 0).unwrap();
        println!("eBPF program attached successfully");

        // 初始化 map
        let mut bytes_sent_map = aya::maps::HashMap::try_from(ebpf.map_mut("bytes_sent").unwrap()).unwrap();
        println!("Map initialized successfully");

        let mut interval = time::interval(Duration::from_secs(60));
        println!("Starting traffic monitoring...");
        loop {
            interval.tick().await;
            
            // 获取当前所有进程的流量数据
            let mut process_traffic: HashMap<u32, u64> = HashMap::new();
            
            // 获取所有当前有流量的进程数据
            for entry in bytes_sent_map.iter() {
                match entry {
                    Ok((pid, bytes)) => {
                        if bytes > 0 {
                            process_traffic.insert(pid, bytes);
                            debug!("Found traffic for PID {}: {} bytes", pid, bytes);
                        }
                    }
                    Err(e) => {
                        error!("Error reading map entry: {:?}", e);
                        continue;
                    }
                }
            }

            // 打印每个进程的流量
            println!("\nTraffic stats for last minute:");
            println!("PID\tProcess Name\tBytes Sent");
            println!("----------------------------------------");
            
            if process_traffic.is_empty() {
                println!("No traffic detected in the last minute");
            } else {
                for (pid, bytes) in process_traffic.iter() {
                    // 获取进程名称
                    let process_name = Command::new("ps")
                        .args(["-p", &pid.to_string(), "-o", "comm="])
                        .output()
                        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
                        .unwrap_or_else(|_| "unknown".to_string());

                    println!("{}\t{}\t{}", pid, process_name, bytes);
                    
                    // 重置计数器
                    match bytes_sent_map.remove(&pid) {
                        Ok(_) => debug!("Successfully reset counter for PID {}", pid),
                        Err(e) => error!("Failed to reset counter for PID {}: {:?}", pid, e),
                    }
                }
            }
            println!("----------------------------------------\n");
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

