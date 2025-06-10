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

nohup ./traa -r r.json -v info > info.log 2>&1 &