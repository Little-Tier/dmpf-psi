# DMPF-PSI

An implementation of PSI protocols based on Distributed Multi-Point Functions (DMPF), also supporting PSI in updatable scenarios.

## ⚠️ Warning

This repository is a research prototype designed to demonstrate the performance and showcase the functionality of our DMPF-based PSI and UPSI protocols. It is intended for experimental or research purposes only and is **NOT** intended to be considered as "production-ready".


## 🌟 Features

### Multiple DMPF-based PSI Implementations

Supports four DMPF-based PSI implementation schemes:
- **DPF DMPF**: Basic implementation based on Distributed Point Functions
- **Batch Code DMPF**: Implementation optimized with batch coding
- **Big-State DMPF**: Implementation with Big-state DMPF
- **OKVS DMPF**: Implementation based on Oblivious Key-Value Store

### PSI Extended Functionalities
- **PSI**: Standard Private Set Intersection, allowing two parties to compute the intersection of their sets without revealing any additional information
- **PSI-CA**: PSI-Cardinality, used to calculate the size of the intersection between two sets
- **PSI-Sum**: Computes the sum of values associated with elements in the intersection

### Optimization Features
- Two-phase optimization design (offline/online)
- Complete performance testing and correctness verification

### DMPF-based UPSI Implementation
- UPSI and extensions including UPSI-CA and UPSI-Sum, implemented based on DMPF
- Comprehensive performance evaluations and correctness verification


## 🛠️ Building Locally

### Prerequisites
```bash
Rust nightly (automatically managed via rust-toolchain.toml)
├── Cargo (package manager, installed with Rust)
└── rustc (compiler, installed with Rust)
```


### Building the Project
```bash
git clone https://github.com/Little-Tier/dmpf-psi.git
cd dmpf-psi-main
cargo build --release
```

## 📊 Benchmarking
All benchmarks are located in the ```benches``` directory.

### PSI Benchmarks
You can modify **PSI_SET_SIZES** in the code to adjust test set sizes for benchmarking.

- **Basic PSI Tests:**
```bash
cargo bench --bench psi_okvs        # PSI benchmark based on OKVS-based DMPF
cargo bench --bench psi_big_state   # PSI benchmark based on Big-state DMPF
cargo bench --bench psi_dpf         # PSI benchmark based on DPF-based DMPF
cargo bench --bench psi_batch_code  # PSI benchmark based on PBC-based DMPF
```

- **PSI Extension Tests:**
```bash
cargo bench --bench psi_ca_okvs     # PSI-CA benchmark based on OKVS-based DMPF
cargo bench --bench psi_sum_okvs    # PSI-Sum benchmark based on OKVS-based DMPF
```

### UPSI Benchmarks
For scenarios such as N=2<sup>16</sup>, N<sub>d</sub>=2<sup>6</sup>, we want to run the protocol on the day when the total input set cardinality reaches N, rather than simulating all 2<sup>16</sup>/2<sup>6</sup>=1024 days. Our UPSI benchmarks simulate the update from day 1023 to day 1024.

You can modify **UPSI_TOTAL_SET_SIZES** and **UPSI_DAILY_UPDATE_SIZES** in the code to adjust the total set size and update set size for benchmarking.

- **UPSI Tests:**
```bash
cargo bench --bench upsi_okvs       # UPSI benchmark based on OKVS-based DMPF
cargo bench --bench upsi_ca_okvs    # UPSI-CA benchmark based on OKVS-based DMPF
cargo bench --bench upsi_sum_okvs   # UPSI-Sum benchmark based on OKVS-based DMPF
```

## 📈 Test Results
All test results mentioned above are saved in the ```data``` directory, where you can view offline/online runtime, intersection calculation results, correctness verification information, and more.
