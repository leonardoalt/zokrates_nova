# ZoKrates + Nova

- [ZoKrates](zokrates.github.io/) is a toolbox for zkSNARKs on Ethereum. 
- [Nova](https://github.com/microsoft/Nova) is a high-speed recursive SNARK.
- ZoKrates is [adding support](https://github.com/Zokrates/ZoKrates/pull/1235) for Nova.

This repository contains examples of how to use ZoKrates to generate recursive
SNARKs with Nova via the CLI and Rust. We also perform comparisons with other
proof systems on specific applications.

# Dependencies

- Rust
- ZoKrates from the `zokrates-nova` branch

# Keccak

`Keccak` can be a major bottleneck for zkevms, so any improvements in `keccak`
computation inside a SNARK can reduce proving time for L2s. We experiment here
with different proof systems to compare the performance of aggregating a
sequence of `keccak` hashes, always over two 256-bit numbers.

The experiment is very preliminary and needs more features.

To run the numbers yourself:

1. Compile the ZoKrates `keccak` program for Nova (using the [Pallas](https://github.com/zcash/pasta)) curve.
```bash
$ cd circuits/keccak_nova && make
```

2. Compile the ZoKrates code for Groth16  (using bn128 by default).
```bash
$ cd circuits/keccak_groth16
$ make
$ make setup
```

3. Run the Rust tests:
```bash
$ cargo test --release -- --nocapture
```

By default the test runs a sequence of 2 hashes on each proof system.  If you
want to change the length of the sequence, change `SEQ_LEN` in
`keccak/src/lib.rs` and `N_STEPS` in `circuits/keccak_nova/keccak.zok`.

4. To run the standalone example:
```bash
$ cargo run --release --example keccak -- --nocapture
```


TODO:

- [ ] Generate input randomly
- [ ] Create comparison table at the end
- [ ] Nova can likely be optimized further
- [ ] Add STARK
- [ ] Add Halo2
