# valkyrie-rs

valkyrie-rs project. Rust binary Emulator

# why ?

Fast Fuzzing is difficult : qiling/qemu is slow. This project aim to develop a rust binary emulator that can be binded to libafl project for fast fuzzing.

# Install

```
git clone https://github.com/0xMirasio/valkyrie-rs.git --recurse --depth 1
cd valkyrie-rs
cargo build --release
```

