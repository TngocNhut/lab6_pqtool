# Lab 6 — Post-Quantum Signatures & Certificates

Họ tên: Trần Ngọc Nhất
MSSV: 24162086

## Goals

This lab implements a post-quantum cryptography command-line tool for:

- ML-DSA key generation, detached signing, and verification
- ML-KEM key generation, encapsulation, and decapsulation
- A minimal ML-DSA-signed certificate structure
- Negative tests for tampering and wrong-key cases
- Benchmarking on Windows and Linux

## Required algorithms

- ML-DSA-44
- ML-KEM-512

Optional extensions:

- ML-DSA-65
- ML-KEM-768

## Chạy lệnh Build trên Windows MSYS2 UCRT64

```bash
cmake -S . -B build-windows-ucrt64 -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-windows-ucrt64
./build-windows-ucrt64/pqtool.exe version
./build-windows-ucrt64/pqtool.exe envcheck
./scripts/check_openssl_pqc.sh
Build on Linux
cmake -S . -B build-linux -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux
./build-linux/pqtool version
Security notes

This project is for offline educational use only. All generated keys, signatures, ciphertexts, and shared secrets are test artifacts.
