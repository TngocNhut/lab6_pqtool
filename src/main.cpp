#include "pqtool/file_utils.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <cstdlib>
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
        << "  pqtool sign --algo mldsa-44 --priv priv.pem --in msg.bin --out sig.bin\n"
        << "  pqtool verify --algo mldsa-44 --pub pub.pem --in msg.bin --sig sig.bin\n"
        << "  pqtool encaps --algo mlkem-512 --pub pub.pem --ct ct.bin --ss ss.bin\n"
        << "  pqtool decaps --algo mlkem-512 --priv priv.pem --ct ct.bin --ss ss.bin\n"
        << "  pqtool cert-create --subject NAME --ca-priv ca.pem --subject-pub subject.pem --out cert.json\n"
        << "  pqtool cert-verify --ca-pub ca_pub.pem --cert cert.json\n"
        << "  pqtool bench --out artifacts/windows/benchmark/bench_pq_windows.csv\n\n"
        << "Algorithms planned:\n"
        << "  mldsa-44    ML-DSA Level 2 signature\n"
        << "  mldsa-65    ML-DSA Level 3 signature, optional extension\n"
        << "  mlkem-512   ML-KEM Level 2 KEM\n"
        << "  mlkem-768   ML-KEM Level 3 KEM, optional extension\n";
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

    std::cout << "[INFO] Detailed PQC algorithm listing must be checked with:\n";
    std::cout << "       scripts/check_openssl_pqc.sh\n";
}

int not_implemented_yet(const std::string& command) {
    std::cerr << "ERROR: command not implemented yet in checkpoint 1: " << command << "\n";
    std::cerr << "Run envcheck first, then implement backend based on local OpenSSL PQC support.\n";
    return 2;
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

        if (
            command == "keygen" ||
            command == "sign" ||
            command == "verify" ||
            command == "encaps" ||
            command == "decaps" ||
            command == "cert-create" ||
            command == "cert-verify" ||
            command == "bench"
        ) {
            return not_implemented_yet(command);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        return 1;

    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
