The interpreter for Swpp 2024 class assembly programs written in Rust.



## Build
First, you need to install the [rustup](https://www.rust-lang.org/tools/install). This process will install `rustc` and `Cargo`.

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Now you have several options.

- `Cargo run --release -- [Assembly File path]`: run the interpreter directly.

- `Cargo build --release`: build the binary at `./target/release/main`.