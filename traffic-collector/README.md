cargo generate --git https://github.com/aya-rs/aya-template.git --name traffic-collector

cargo install bpf-linker

rustup install nightly

rustup default stable

rustup override set nightly

rustup component add rust-src --toolchain nightly

cargo +nightly build --release -Z build-std=core --target bpfel-unknown-none

cargo run --release

rm /lib/modules/$(uname -r)/build

ln -s /usr/src/kernels/3.10.0-1160.119.1.el7.x86_64 /lib/modules/$(uname -r)/build

yum install -y bcc bcc-tools

nohup ./traa -r r.json -L info > info.log 2>&1 &

现在程序应该能正常运行了。使用：
-L debug 设置日志级别为 debug
-v 1 设置详细级别为 debug
-t 10 设置统计时长为 10 秒
-r rules.json 指定规则文件


