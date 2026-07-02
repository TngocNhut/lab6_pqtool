#!/usr/bin/env bash
set -euo pipefail

mkdir -p artifacts/windows/env

{
  echo "===== OpenSSL version ====="
  openssl version -a || true

  echo
  echo "===== Providers ====="
  openssl list -providers || true

  echo
  echo "===== Signature algorithms matching PQC ====="
  openssl list -signature-algorithms | grep -Ei "ML-DSA|Dilithium|PQC|post|mldsa" || true

  echo
  echo "===== KEM algorithms matching PQC ====="
  openssl list -kem-algorithms | grep -Ei "ML-KEM|Kyber|PQC|post|mlkem|kem" || true

  echo
  echo "===== Public key algorithms matching PQC ====="
  openssl list -public-key-algorithms | grep -Ei "ML-DSA|ML-KEM|Dilithium|Kyber|PQC|post|mldsa|mlkem" || true

  echo
  echo "===== Try pkeyutl help ====="
  openssl pkeyutl -help 2>&1 | head -120 || true

} | tee artifacts/windows/env/openssl_pqc_capabilities.log
