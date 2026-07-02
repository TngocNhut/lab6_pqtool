#!/usr/bin/env bash
set -euo pipefail

BIN="./build-windows-ucrt64/pqtool.exe"
ART="artifacts/windows"

mkdir -p "$ART/keys" "$ART/signatures" "$ART/kem" "$ART/certs" "$ART/benchmark" "$ART/env" samples

echo "===== LAB 6 WINDOWS DEMO ====="

echo
echo "===== VERSION AND ENVIRONMENT ====="
$BIN version
$BIN envcheck

echo
echo "===== OPENSSL PQC CAPABILITY CHECK ====="
./scripts/check_openssl_pqc.sh > "$ART/env/openssl_pqc_capabilities_demo.log"
grep -Ei "ML-DSA-44|ML-DSA-65|ML-KEM-512|ML-KEM-768" "$ART/env/openssl_pqc_capabilities_demo.log" | head -20

echo
echo "===== MESSAGE ====="
cat > samples/demo_message.txt <<'TXT'
Lab 6 Windows demo message.
Student: Tran Ngoc Nhat.
Purpose: post-quantum ML-DSA and ML-KEM operations.
TXT

cat samples/demo_message.txt

echo
echo "===== ML-DSA-44 KEYGEN / SIGN / VERIFY ====="
$BIN keygen \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_mldsa44_pub.pem" \
  --priv "$ART/keys/demo_mldsa44_priv.pem"

$BIN keyinfo --key "$ART/keys/demo_mldsa44_pub.pem"

$BIN sign \
  --algo mldsa-44 \
  --priv "$ART/keys/demo_mldsa44_priv.pem" \
  --in samples/demo_message.txt \
  --out "$ART/signatures/demo_message_mldsa44.sig"

$BIN verify \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_mldsa44_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_mldsa44.sig"

echo
echo "===== ML-DSA-65 KEYGEN / SIGN / VERIFY ====="
$BIN keygen \
  --algo mldsa-65 \
  --pub "$ART/keys/demo_mldsa65_pub.pem" \
  --priv "$ART/keys/demo_mldsa65_priv.pem"

$BIN keyinfo --key "$ART/keys/demo_mldsa65_pub.pem"

$BIN sign \
  --algo mldsa-65 \
  --priv "$ART/keys/demo_mldsa65_priv.pem" \
  --in samples/demo_message.txt \
  --out "$ART/signatures/demo_message_mldsa65.sig"

$BIN verify \
  --algo mldsa-65 \
  --pub "$ART/keys/demo_mldsa65_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_mldsa65.sig"

echo
echo "===== ML-KEM-512 KEYGEN / ENCAPS / DECAPS ====="
$BIN keygen \
  --algo mlkem-512 \
  --pub "$ART/keys/demo_mlkem512_pub.pem" \
  --priv "$ART/keys/demo_mlkem512_priv.pem"

$BIN keyinfo --key "$ART/keys/demo_mlkem512_pub.pem"

$BIN encaps \
  --algo mlkem-512 \
  --pub "$ART/keys/demo_mlkem512_pub.pem" \
  --ct "$ART/kem/demo_mlkem512_ct.bin" \
  --ss "$ART/kem/demo_mlkem512_ss_enc.bin"

$BIN decaps \
  --algo mlkem-512 \
  --priv "$ART/keys/demo_mlkem512_priv.pem" \
  --ct "$ART/kem/demo_mlkem512_ct.bin" \
  --ss "$ART/kem/demo_mlkem512_ss_dec.bin"

cmp -s "$ART/kem/demo_mlkem512_ss_enc.bin" "$ART/kem/demo_mlkem512_ss_dec.bin" \
  && echo "[OK] ML-KEM-512 shared secrets match" \
  || { echo "[FAIL] ML-KEM-512 shared secrets differ"; exit 1; }

echo
echo "===== ML-KEM-768 KEYGEN / ENCAPS / DECAPS ====="
$BIN keygen \
  --algo mlkem-768 \
  --pub "$ART/keys/demo_mlkem768_pub.pem" \
  --priv "$ART/keys/demo_mlkem768_priv.pem"

$BIN keyinfo --key "$ART/keys/demo_mlkem768_pub.pem"

$BIN encaps \
  --algo mlkem-768 \
  --pub "$ART/keys/demo_mlkem768_pub.pem" \
  --ct "$ART/kem/demo_mlkem768_ct.bin" \
  --ss "$ART/kem/demo_mlkem768_ss_enc.bin"

$BIN decaps \
  --algo mlkem-768 \
  --priv "$ART/keys/demo_mlkem768_priv.pem" \
  --ct "$ART/kem/demo_mlkem768_ct.bin" \
  --ss "$ART/kem/demo_mlkem768_ss_dec.bin"

cmp -s "$ART/kem/demo_mlkem768_ss_enc.bin" "$ART/kem/demo_mlkem768_ss_dec.bin" \
  && echo "[OK] ML-KEM-768 shared secrets match" \
  || { echo "[FAIL] ML-KEM-768 shared secrets differ"; exit 1; }

echo
echo "===== NEGATIVE TEST: TAMPERED ML-DSA MESSAGE ====="
cp samples/demo_message.txt samples/demo_message_tampered.txt
echo "TAMPERED DATA" >> samples/demo_message_tampered.txt

set +e
$BIN verify \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_mldsa44_pub.pem" \
  --in samples/demo_message_tampered.txt \
  --sig "$ART/signatures/demo_message_mldsa44.sig"
tampered_msg_rc=$?
set -e

if [[ "$tampered_msg_rc" -eq 0 ]]; then
  echo "[FAIL] Tampered ML-DSA message unexpectedly verified"
  exit 1
fi

echo "[OK] Tampered ML-DSA message rejected"

echo
echo "===== NEGATIVE TEST: TAMPERED ML-DSA SIGNATURE ====="
cp "$ART/signatures/demo_message_mldsa44.sig" "$ART/signatures/demo_message_mldsa44_tampered.sig"

python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/signatures/demo_message_mldsa44_tampered.sig")
data = bytearray(p.read_bytes())
data[-1] ^= 0x01
p.write_bytes(data)
print("[OK] Tampered ML-DSA signature")
PY

set +e
$BIN verify \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_mldsa44_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_mldsa44_tampered.sig"
tampered_sig_rc=$?
set -e

if [[ "$tampered_sig_rc" -eq 0 ]]; then
  echo "[FAIL] Tampered ML-DSA signature unexpectedly verified"
  exit 1
fi

echo "[OK] Tampered ML-DSA signature rejected"

echo
echo "===== NEGATIVE TEST: WRONG ML-DSA PUBLIC KEY ====="
$BIN keygen \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_wrong_mldsa44_pub.pem" \
  --priv "$ART/keys/demo_wrong_mldsa44_priv.pem"

set +e
$BIN verify \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_wrong_mldsa44_pub.pem" \
  --in samples/demo_message.txt \
  --sig "$ART/signatures/demo_message_mldsa44.sig"
wrong_sig_key_rc=$?
set -e

if [[ "$wrong_sig_key_rc" -eq 0 ]]; then
  echo "[FAIL] Wrong ML-DSA public key unexpectedly verified"
  exit 1
fi

echo "[OK] Wrong ML-DSA public key rejected"

echo
echo "===== NEGATIVE TEST: TAMPERED ML-KEM CIPHERTEXT ====="
cp "$ART/kem/demo_mlkem512_ct.bin" "$ART/kem/demo_mlkem512_ct_tampered.bin"

python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/kem/demo_mlkem512_ct_tampered.bin")
data = bytearray(p.read_bytes())
data[0] ^= 0x01
p.write_bytes(data)
print("[OK] Tampered ML-KEM ciphertext")
PY

$BIN decaps \
  --algo mlkem-512 \
  --priv "$ART/keys/demo_mlkem512_priv.pem" \
  --ct "$ART/kem/demo_mlkem512_ct_tampered.bin" \
  --ss "$ART/kem/demo_mlkem512_ss_tampered_dec.bin"

cmp -s "$ART/kem/demo_mlkem512_ss_enc.bin" "$ART/kem/demo_mlkem512_ss_tampered_dec.bin" \
  && { echo "[FAIL] Tampered ML-KEM ciphertext produced same shared secret"; exit 1; } \
  || echo "[OK] Tampered ML-KEM ciphertext produced different shared secret"

echo
echo "===== NEGATIVE TEST: WRONG ML-KEM PRIVATE KEY ====="
$BIN keygen \
  --algo mlkem-512 \
  --pub "$ART/keys/demo_wrong_mlkem512_pub.pem" \
  --priv "$ART/keys/demo_wrong_mlkem512_priv.pem"

$BIN decaps \
  --algo mlkem-512 \
  --priv "$ART/keys/demo_wrong_mlkem512_priv.pem" \
  --ct "$ART/kem/demo_mlkem512_ct.bin" \
  --ss "$ART/kem/demo_mlkem512_ss_wrongkey_dec.bin"

cmp -s "$ART/kem/demo_mlkem512_ss_enc.bin" "$ART/kem/demo_mlkem512_ss_wrongkey_dec.bin" \
  && { echo "[FAIL] Wrong ML-KEM private key produced same shared secret"; exit 1; } \
  || echo "[OK] Wrong ML-KEM private key produced different shared secret"

echo
echo "===== NEGATIVE TEST: UNSUPPORTED ALGORITHM ====="
set +e
$BIN keygen \
  --algo dilithium2 \
  --pub "$ART/keys/bad_pub.pem" \
  --priv "$ART/keys/bad_priv.pem"
bad_algo_rc=$?
set -e

if [[ "$bad_algo_rc" -eq 0 ]]; then
  echo "[FAIL] Unsupported algorithm unexpectedly accepted"
  exit 1
fi

echo "[OK] Unsupported algorithm rejected"

echo
echo "===== MINI ML-DSA CERTIFICATE ====="
$BIN keygen \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_ca_mldsa44_pub.pem" \
  --priv "$ART/keys/demo_ca_mldsa44_priv.pem"

$BIN keygen \
  --algo mldsa-44 \
  --pub "$ART/keys/demo_subject_mldsa44_pub.pem" \
  --priv "$ART/keys/demo_subject_mldsa44_priv.pem"

$BIN cert-create \
  --subject "Tran Ngoc Nhat Lab6 Subject" \
  --ca-priv "$ART/keys/demo_ca_mldsa44_priv.pem" \
  --subject-pub "$ART/keys/demo_subject_mldsa44_pub.pem" \
  --out "$ART/certs/demo_subject_cert.json"

$BIN cert-verify \
  --ca-pub "$ART/keys/demo_ca_mldsa44_pub.pem" \
  --cert "$ART/certs/demo_subject_cert.json"

cp "$ART/certs/demo_subject_cert.json" "$ART/certs/demo_subject_cert_tampered.json"

python3 - <<'PY'
from pathlib import Path
p = Path("artifacts/windows/certs/demo_subject_cert_tampered.json")
s = p.read_text()
s = s.replace("Tran Ngoc Nhat Lab6 Subject", "Tran Ngoc Nhat Lab6 Attacker")
p.write_text(s)
print("[OK] Tampered mini certificate subject")
PY

set +e
$BIN cert-verify \
  --ca-pub "$ART/keys/demo_ca_mldsa44_pub.pem" \
  --cert "$ART/certs/demo_subject_cert_tampered.json"
tampered_cert_rc=$?
set -e

if [[ "$tampered_cert_rc" -eq 0 ]]; then
  echo "[FAIL] Tampered mini certificate unexpectedly verified"
  exit 1
fi

echo "[OK] Tampered mini ML-DSA certificate rejected"

echo
echo "===== PQ BENCHMARK ====="
$BIN bench --out "$ART/benchmark/demo_bench_pq_windows.csv" \
  > "$ART/benchmark/demo_bench_pq_windows.log" 2>&1

grep "avg_ms\|PQ benchmark completed" "$ART/benchmark/demo_bench_pq_windows.log"
cat "$ART/benchmark/demo_bench_pq_windows.csv"

echo
echo "[OK] Lab 6 Windows demo completed successfully."
