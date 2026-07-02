#include "pqtool/pq_crypto.hpp"
#include "pqtool/file_utils.hpp"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace pqtool {

namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* p) const {
        EVP_PKEY_free(p);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const {
        EVP_PKEY_CTX_free(p);
    }
};

struct EvpSignatureDeleter {
    void operator()(EVP_SIGNATURE* p) const {
        EVP_SIGNATURE_free(p);
    }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;
using EvpSignaturePtr = std::unique_ptr<EVP_SIGNATURE, EvpSignatureDeleter>;

std::string openssl_error_string() {
    char buf[256] = {};
    const unsigned long err = ERR_get_error();

    if (err == 0) {
        return "unknown OpenSSL error";
    }

    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

void ensure_ok(int rc, const std::string& what) {
    if (rc != 1) {
        throw std::runtime_error(what + ": " + openssl_error_string());
    }
}

std::string lower_copy(std::string s) {
    std::transform(
        s.begin(),
        s.end(),
        s.begin(),
        [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        }
    );

    return s;
}

std::string ossl_name_for_algo(const std::string& algo) {
    const std::string a = lower_copy(algo);

    if (a == "mldsa-44") {
        return "ML-DSA-44";
    }

    if (a == "mldsa-65") {
        return "ML-DSA-65";
    }

    if (a == "mlkem-512") {
        return "ML-KEM-512";
    }

    if (a == "mlkem-768") {
        return "ML-KEM-768";
    }

    throw std::runtime_error("unsupported algorithm: " + algo);
}

EvpPkeyPtr load_public_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("cannot open public key PEM: " + path);
    }

    EVP_PKEY* raw = PEM_read_PUBKEY(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!raw) {
        throw std::runtime_error("cannot parse public key PEM: " + path);
    }

    return EvpPkeyPtr(raw);
}

EvpPkeyPtr load_private_key_pem(const std::string& path) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        throw std::runtime_error("cannot open private key PEM: " + path);
    }

    EVP_PKEY* raw = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);

    if (!raw) {
        throw std::runtime_error("cannot parse private key PEM: " + path);
    }

    return EvpPkeyPtr(raw);
}

void save_private_key_pem(EVP_PKEY* key, const std::string& path) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open private key output: " + path);
    }

    const int rc = PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    ensure_ok(rc, "PEM_write_PrivateKey failed");
}

void save_public_key_pem(EVP_PKEY* key, const std::string& path) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open public key output: " + path);
    }

    const int rc = PEM_write_PUBKEY(f, key);
    fclose(f);

    ensure_ok(rc, "PEM_write_PUBKEY failed");
}

void save_private_key_der(EVP_PKEY* key, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open private DER output: " + path);
    }

    const int rc = i2d_PrivateKey_fp(f, key);
    fclose(f);

    ensure_ok(rc, "i2d_PrivateKey_fp failed");
}

void save_public_key_der(EVP_PKEY* key, const std::string& path) {
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) {
        throw std::runtime_error("cannot open public DER output: " + path);
    }

    const int rc = i2d_PUBKEY_fp(f, key);
    fclose(f);

    ensure_ok(rc, "i2d_PUBKEY_fp failed");
}

std::string replace_extension(const std::string& path, const std::string& ext) {
    std::filesystem::path p(path);
    p.replace_extension(ext);
    return p.string();
}

} // namespace

bool is_mldsa_algo(const std::string& algo) {
    const std::string a = lower_copy(algo);
    return a == "mldsa-44" || a == "mldsa-65";
}

bool is_mlkem_algo(const std::string& algo) {
    const std::string a = lower_copy(algo);
    return a == "mlkem-512" || a == "mlkem-768";
}

bool is_supported_algo(const std::string& algo) {
    return is_mldsa_algo(algo) || is_mlkem_algo(algo);
}

void generate_keypair(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& private_pem_path
) {
    if (!is_supported_algo(algo)) {
        throw std::runtime_error("unsupported algorithm: " + algo);
    }

    const std::string ossl_name = ossl_name_for_algo(algo);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_name(nullptr, ossl_name.c_str(), nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed for " + ossl_name + ": " + openssl_error_string());
    }

    ensure_ok(EVP_PKEY_keygen_init(ctx.get()), "EVP_PKEY_keygen_init failed");

    EVP_PKEY* raw = nullptr;
    ensure_ok(EVP_PKEY_keygen(ctx.get(), &raw), "EVP_PKEY_keygen failed");

    EvpPkeyPtr key(raw);

    save_private_key_pem(key.get(), private_pem_path);
    save_public_key_pem(key.get(), public_pem_path);
    save_private_key_der(key.get(), replace_extension(private_pem_path, ".der"));
    save_public_key_der(key.get(), replace_extension(public_pem_path, ".der"));

    std::cout << "[OK] Generated post-quantum key pair\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] OpenSSL name: " << ossl_name << "\n";
    std::cout << "[OK] Public PEM: " << public_pem_path << "\n";
    std::cout << "[OK] Private PEM: " << private_pem_path << "\n";
    std::cout << "[OK] Public DER: " << replace_extension(public_pem_path, ".der") << "\n";
    std::cout << "[OK] Private DER: " << replace_extension(private_pem_path, ".der") << "\n";

    if (is_mldsa_algo(algo)) {
        std::cout << "[INFO] Type: ML-DSA post-quantum digital signature\n";
    }

    if (is_mlkem_algo(algo)) {
        std::cout << "[INFO] Type: ML-KEM post-quantum key encapsulation mechanism\n";
    }
}

void print_key_info(const std::string& key_path) {
    EvpPkeyPtr key;

    try {
        key = load_public_key_pem(key_path);
    } catch (...) {
        key = load_private_key_pem(key_path);
    }

    const char* type_name = EVP_PKEY_get0_type_name(key.get());
    if (!type_name) {
        type_name = "unknown";
    }

    std::cout << "[OK] Key file: " << key_path << "\n";
    std::cout << "[OK] OpenSSL key type: " << type_name << "\n";

    const std::string tn = type_name;

    if (tn.find("ML-DSA") != std::string::npos || tn.find("MLDSA") != std::string::npos) {
        std::cout << "[INFO] Key usage: digital signature\n";
    } else if (tn.find("ML-KEM") != std::string::npos || tn.find("MLKEM") != std::string::npos) {
        std::cout << "[INFO] Key usage: key encapsulation mechanism\n";
    }
}

void sign_file_detached(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& input_path,
    const std::string& signature_path
) {
    if (!is_mldsa_algo(algo)) {
        throw std::runtime_error("sign requires ML-DSA algorithm, got: " + algo);
    }

    const std::vector<uint8_t> message = read_binary_file(input_path);
    EvpPkeyPtr key = load_private_key_pem(private_pem_path);

    const std::string ossl_name = ossl_name_for_algo(algo);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_pkey failed: " + openssl_error_string());
    }

    EvpSignaturePtr sig_alg(EVP_SIGNATURE_fetch(nullptr, ossl_name.c_str(), nullptr));
    if (!sig_alg) {
        throw std::runtime_error("EVP_SIGNATURE_fetch failed for " + ossl_name + ": " + openssl_error_string());
    }

    ensure_ok(
        EVP_PKEY_sign_message_init(ctx.get(), sig_alg.get(), nullptr),
        "EVP_PKEY_sign_message_init failed"
    );

    size_t sig_len = 0;

    ensure_ok(
        EVP_PKEY_sign(ctx.get(), nullptr, &sig_len, message.data(), message.size()),
        "EVP_PKEY_sign length query failed"
    );

    std::vector<uint8_t> signature(sig_len);

    ensure_ok(
        EVP_PKEY_sign(ctx.get(), signature.data(), &sig_len, message.data(), message.size()),
        "EVP_PKEY_sign failed"
    );

    signature.resize(sig_len);
    write_binary_file(signature_path, signature);

    std::cout << "[OK] ML-DSA detached signature created\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Input file: " << input_path << "\n";
    std::cout << "[OK] Input size: " << message.size() << " bytes\n";
    std::cout << "[OK] Private key: " << private_pem_path << "\n";
    std::cout << "[OK] Signature file: " << signature_path << "\n";
    std::cout << "[OK] Signature size: " << signature.size() << " bytes\n";
}

bool verify_file_detached(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& input_path,
    const std::string& signature_path
) {
    if (!is_mldsa_algo(algo)) {
        throw std::runtime_error("verify requires ML-DSA algorithm, got: " + algo);
    }

    const std::vector<uint8_t> message = read_binary_file(input_path);
    const std::vector<uint8_t> signature = read_binary_file(signature_path);
    EvpPkeyPtr key = load_public_key_pem(public_pem_path);

    const std::string ossl_name = ossl_name_for_algo(algo);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_pkey failed: " + openssl_error_string());
    }

    EvpSignaturePtr sig_alg(EVP_SIGNATURE_fetch(nullptr, ossl_name.c_str(), nullptr));
    if (!sig_alg) {
        throw std::runtime_error("EVP_SIGNATURE_fetch failed for " + ossl_name + ": " + openssl_error_string());
    }

    ensure_ok(
        EVP_PKEY_verify_message_init(ctx.get(), sig_alg.get(), nullptr),
        "EVP_PKEY_verify_message_init failed"
    );

    const int rc = EVP_PKEY_verify(
        ctx.get(),
        signature.data(),
        signature.size(),
        message.data(),
        message.size()
    );

    if (rc == 1) {
        std::cout << "[OK] ML-DSA signature verification succeeded\n";
        std::cout << "[OK] Algorithm: " << algo << "\n";
        std::cout << "[OK] Input file: " << input_path << "\n";
        std::cout << "[OK] Public key: " << public_pem_path << "\n";
        std::cout << "[OK] Signature file: " << signature_path << "\n";
        std::cout << "[OK] Signature size: " << signature.size() << " bytes\n";
        return true;
    }

    if (rc == 0) {
        std::cout << "[FAIL] ML-DSA signature verification failed\n";
        std::cout << "[INFO] Algorithm: " << algo << "\n";
        std::cout << "[INFO] Input file: " << input_path << "\n";
        std::cout << "[INFO] Public key: " << public_pem_path << "\n";
        std::cout << "[INFO] Signature file: " << signature_path << "\n";
        return false;
    }

    throw std::runtime_error("EVP_PKEY_verify error: " + openssl_error_string());
}

void kem_encapsulate(
    const std::string& algo,
    const std::string& public_pem_path,
    const std::string& ciphertext_path,
    const std::string& shared_secret_path
) {
    if (!is_mlkem_algo(algo)) {
        throw std::runtime_error("encaps requires ML-KEM algorithm, got: " + algo);
    }

    EvpPkeyPtr key = load_public_key_pem(public_pem_path);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_pkey failed: " + openssl_error_string());
    }

    ensure_ok(EVP_PKEY_encapsulate_init(ctx.get(), nullptr), "EVP_PKEY_encapsulate_init failed");

    size_t ct_len = 0;
    size_t ss_len = 0;

    ensure_ok(
        EVP_PKEY_encapsulate(ctx.get(), nullptr, &ct_len, nullptr, &ss_len),
        "EVP_PKEY_encapsulate length query failed"
    );

    std::vector<uint8_t> ciphertext(ct_len);
    std::vector<uint8_t> shared_secret(ss_len);

    ensure_ok(
        EVP_PKEY_encapsulate(
            ctx.get(),
            ciphertext.data(),
            &ct_len,
            shared_secret.data(),
            &ss_len
        ),
        "EVP_PKEY_encapsulate failed"
    );

    ciphertext.resize(ct_len);
    shared_secret.resize(ss_len);

    write_binary_file(ciphertext_path, ciphertext);
    write_binary_file(shared_secret_path, shared_secret);

    std::cout << "[OK] ML-KEM encapsulation succeeded\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Public key: " << public_pem_path << "\n";
    std::cout << "[OK] Ciphertext file: " << ciphertext_path << "\n";
    std::cout << "[OK] Ciphertext size: " << ciphertext.size() << " bytes\n";
    std::cout << "[OK] Shared secret file: " << shared_secret_path << "\n";
    std::cout << "[OK] Shared secret size: " << shared_secret.size() << " bytes\n";
    std::cout << "[INFO] Shared secret hex prefix: " << bytes_to_hex(shared_secret, 32) << "\n";
}

void kem_decapsulate(
    const std::string& algo,
    const std::string& private_pem_path,
    const std::string& ciphertext_path,
    const std::string& shared_secret_path
) {
    if (!is_mlkem_algo(algo)) {
        throw std::runtime_error("decaps requires ML-KEM algorithm, got: " + algo);
    }

    EvpPkeyPtr key = load_private_key_pem(private_pem_path);
    const std::vector<uint8_t> ciphertext = read_binary_file(ciphertext_path);

    EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_pkey failed: " + openssl_error_string());
    }

    ensure_ok(EVP_PKEY_decapsulate_init(ctx.get(), nullptr), "EVP_PKEY_decapsulate_init failed");

    size_t ss_len = 0;

    ensure_ok(
        EVP_PKEY_decapsulate(
            ctx.get(),
            nullptr,
            &ss_len,
            ciphertext.data(),
            ciphertext.size()
        ),
        "EVP_PKEY_decapsulate length query failed"
    );

    std::vector<uint8_t> shared_secret(ss_len);

    ensure_ok(
        EVP_PKEY_decapsulate(
            ctx.get(),
            shared_secret.data(),
            &ss_len,
            ciphertext.data(),
            ciphertext.size()
        ),
        "EVP_PKEY_decapsulate failed"
    );

    shared_secret.resize(ss_len);
    write_binary_file(shared_secret_path, shared_secret);

    std::cout << "[OK] ML-KEM decapsulation completed\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Private key: " << private_pem_path << "\n";
    std::cout << "[OK] Ciphertext file: " << ciphertext_path << "\n";
    std::cout << "[OK] Ciphertext size: " << ciphertext.size() << " bytes\n";
    std::cout << "[OK] Shared secret file: " << shared_secret_path << "\n";
    std::cout << "[OK] Shared secret size: " << shared_secret.size() << " bytes\n";
    std::cout << "[INFO] Shared secret hex prefix: " << bytes_to_hex(shared_secret, 32) << "\n";
}

} // namespace pqtool
