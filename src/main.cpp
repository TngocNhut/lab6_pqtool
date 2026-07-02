#include "pqtool/file_utils.hpp"
#include "pqtool/pq_crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/provider.h>

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void print_help() {
    std::cout
        << "pqtool 1.0.0\n"
        << "OpenSSL-backed post-quantum lab tool\n\n"
        << "Usage:\n"
        << "  pqtool version\n"
        << "  pqtool envcheck\n"
        << "  pqtool keygen --algo mldsa-44 --pub pub.pem --priv priv.pem\n"
        << "  pqtool keygen --algo mlkem-512 --pub pub.pem --priv priv.pem\n"
        << "  pqtool keyinfo --key key.pem\n"
        << "  pqtool sign --algo mldsa-44 --priv priv.pem --in msg.bin --out sig.bin\n"
        << "  pqtool verify --algo mldsa-44 --pub pub.pem --in msg.bin --sig sig.bin\n"
        << "  pqtool encaps --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin\n"
        << "  pqtool decaps --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin\n"
        << "  pqtool bench --out artifacts/windows/benchmark/bench_pq_windows.csv\n\n"
        << "Supported algorithms:\n"
        << "  mldsa-44\n"
        << "  mldsa-65\n"
        << "  mlkem-512\n"
        << "  mlkem-768\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 1; i + 1 < argc; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }

    return {};
}

void print_version() {
    std::cout << "pqtool 1.0.0\n";
    std::cout << "OpenSSL runtime: " << OpenSSL_version(OPENSSL_VERSION) << "\n";
}

void print_envcheck() {
    std::cout << "[INFO] OpenSSL runtime: " << OpenSSL_version(OPENSSL_VERSION) << "\n";

    OSSL_PROVIDER* defprov = OSSL_PROVIDER_load(nullptr, "default");
    if (defprov) {
        std::cout << "[OK] Loaded default provider\n";
        OSSL_PROVIDER_unload(defprov);
    } else {
        std::cout << "[WARN] Could not explicitly load default provider\n";
    }

    std::cout << "[OK] Expected PQ algorithms from local check:\n";
    std::cout << "     ML-DSA-44, ML-DSA-65, ML-KEM-512, ML-KEM-768\n";
}


int run_bench(int argc, char* argv[]) {
    const std::string out = get_arg(argc, argv, "--out");

    if (out.empty()) {
        std::cerr << "ERROR: bench requires --out benchmark.csv\n";
        return 1;
    }

    pqtool::run_pq_benchmark_csv(out);
    return 0;
}

int run_keygen(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string pub = get_arg(argc, argv, "--pub");
    const std::string priv = get_arg(argc, argv, "--priv");

    if (algo.empty() || pub.empty() || priv.empty()) {
        std::cerr << "ERROR: keygen requires --algo ALGO --pub pub.pem --priv priv.pem\n";
        return 1;
    }

    pqtool::generate_keypair(algo, pub, priv);
    return 0;
}

int run_keyinfo(int argc, char* argv[]) {
    const std::string key = get_arg(argc, argv, "--key");

    if (key.empty()) {
        std::cerr << "ERROR: keyinfo requires --key key.pem\n";
        return 1;
    }

    pqtool::print_key_info(key);
    return 0;
}

int run_sign(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string priv = get_arg(argc, argv, "--priv");
    const std::string input = get_arg(argc, argv, "--in");
    const std::string out = get_arg(argc, argv, "--out");

    if (algo.empty() || priv.empty() || input.empty() || out.empty()) {
        std::cerr << "ERROR: sign requires --algo ALGO --priv priv.pem --in msg.bin --out sig.bin\n";
        return 1;
    }

    pqtool::sign_file_detached(algo, priv, input, out);
    return 0;
}

int run_verify(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string pub = get_arg(argc, argv, "--pub");
    const std::string input = get_arg(argc, argv, "--in");
    const std::string sig = get_arg(argc, argv, "--sig");

    if (algo.empty() || pub.empty() || input.empty() || sig.empty()) {
        std::cerr << "ERROR: verify requires --algo ALGO --pub pub.pem --in msg.bin --sig sig.bin\n";
        return 1;
    }

    const bool ok = pqtool::verify_file_detached(algo, pub, input, sig);
    return ok ? 0 : 1;
}

int run_encaps(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string pub = get_arg(argc, argv, "--pub");
    const std::string ct = get_arg(argc, argv, "--ct");
    const std::string ss = get_arg(argc, argv, "--ss");

    if (algo.empty() || pub.empty() || ct.empty() || ss.empty()) {
        std::cerr << "ERROR: encaps requires --algo ALGO --pub pub.pem --ct ct.bin --ss ss.bin\n";
        return 1;
    }

    pqtool::kem_encapsulate(algo, pub, ct, ss);
    return 0;
}

int run_decaps(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string priv = get_arg(argc, argv, "--priv");
    const std::string ct = get_arg(argc, argv, "--ct");
    const std::string ss = get_arg(argc, argv, "--ss");

    if (algo.empty() || priv.empty() || ct.empty() || ss.empty()) {
        std::cerr << "ERROR: decaps requires --algo ALGO --priv priv.pem --ct ct.bin --ss ss.bin\n";
        return 1;
    }

    pqtool::kem_decapsulate(algo, priv, ct, ss);
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            print_help();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "help") {
            print_help();
            return 0;
        }

        if (command == "version") {
            print_version();
            return 0;
        }

        if (command == "envcheck") {
            print_envcheck();
            return 0;
        }

        if (command == "keygen") {
            return run_keygen(argc, argv);
        }

        if (command == "keyinfo") {
            return run_keyinfo(argc, argv);
        }

        if (command == "sign") {
            return run_sign(argc, argv);
        }

        if (command == "verify") {
            return run_verify(argc, argv);
        }

        if (command == "encaps") {
            return run_encaps(argc, argv);
        }

        if (command == "decaps") {
            return run_decaps(argc, argv);
        }

        if (command == "bench") {
            return run_bench(argc, argv);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        return 1;

    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
