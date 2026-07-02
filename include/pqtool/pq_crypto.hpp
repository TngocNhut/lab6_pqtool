#pragma once

#include <string>

namespace pqtool {

bool is_supported_algo(const std::string& algo);
bool is_mldsa_algo(const std::string& algo);
bool is_mlkem_algo(const std::string& algo);

void generate_keypair(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& private_pem_path
);

void print_key_info(
    const std::string& key_path
);

void sign_file_detached(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& input_path,
    const std::string& signature_path
);

bool verify_file_detached(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& input_path,
    const std::string& signature_path
);

void kem_encapsulate(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& ciphertext_path,
    const std::string& shared_secret_path
);

void kem_decapsulate(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& ciphertext_path,
    const std::string& shared_secret_path
);

void run_pq_benchmark_csv(
    const std::string& out_csv
);

void create_mldsa_certificate(
    const std::string& subject,
    const std::string& ca_private_key_path,
    const std::string& subject_public_key_path,
    const std::string& cert_json_path
);

bool verify_mldsa_certificate(
    const std::string& ca_public_key_path,
    const std::string& cert_json_path
);

} // namespace pqtool
