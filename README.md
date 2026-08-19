# Verifiable and Pairing-Free Certificateless Searchable Encryption

This repository contains the LaTeX manuscript, performance plots, Python simulations, and a high-performance native Rust benchmark for the research paper: **"Verifiable and Pairing-Free Certificateless Searchable Encryption with Complete Keyword-Guessing Attack Resistance"**.

## 📁 Repository Structure

- `paper/`: Contains the 10-page expanded LaTeX manuscript (`main.tex`), final compiled PDF (`main.pdf`), bibliography, and authentic EPS plots used for performance evaluation.
- `src/`: Contains the discrete-event Python simulation and plotting scripts.
- `src/cl_se_rust/`: Contains the high-performance native Rust implementation and benchmarking suite, leveraging the `k256` elliptic curve crate.

---

## 🛠️ Setup & Usage Instructions

### 1. Compiling the LaTeX Paper
To compile the manuscript from source, ensure you have a standard TeX Live distribution installed (including `pdflatex` and `latexmk`).
```bash
cd paper
latexmk -pdf main.tex
```
*The final output will be generated as `main.pdf`.*

### 2. Running the Python Simulations & Generating Plots
The Python scripts are used to model the cryptographic operations for constrained IoT edge devices and generate the theoretical complexity EPS graphs used in the paper.

**Prerequisites:** Python 3.x, `matplotlib`, `numpy`, `ecdsa`
```bash
pip install matplotlib numpy ecdsa
```

**To generate the EPS performance plots:**
```bash
cd src
python3 generate_plots.py
```
*This will output `enc_time.eps`, `search_time.eps`, and `comm_cost.eps` directly into the `paper/` directory.*

**To run the Python discrete-event simulator:**
```bash
cd src
python3 simulate_scheme.py
```

### 3. Running the High-Performance Rust Benchmark
To demonstrate extreme scalability on the cloud server backend, the cryptographic search algorithms have been natively implemented in Rust. This benchmark executes the pairing-free scalar multiplication logic and measures execution time at microsecond precision.

**Prerequisites:** [Rust and Cargo](https://rustup.rs/) (edition 2021+)

**To execute the benchmark:**
```bash
cd src/cl_se_rust
cargo run --release
```
*Note: You must use the `--release` flag to enable compiler optimizations (-O3). The Rust implementation achieves sub-millisecond search latencies (approx. 0.059 ms per search), representing a ~50x speedup over the interpreted Python environment.*

---

## 🔒 Security Claims
The implementation within this repository demonstrates:
- **Pairing-Free Efficiency:** Complete elimination of heavy bilinear pairings in favor of lightweight scalar multiplications over `secp256k1`.
- **Dual-KGA Resistance:** Server-bound blinding mechanisms successfully prevent both Inside (IKGA) and Outside (OKGA) Keyword-Guessing Attacks.
- **Verifiable Search:** Integration of Merkle Hash Trees (MHT) allows the Data User to mathematically verify search completeness without blindly trusting the Cloud Server.
