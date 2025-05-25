cargo generate --git https://github.com/aya-rs/aya-template.git --name traffic-collector

cargo install bpf-linker

rustup install nightly

rustup default stable

rustup override set nightly

rustup component add rust-src --toolchain nightly

cargo +nightly build --release -Z build-std=core --target bpfel-unknown-none

cargo run --release