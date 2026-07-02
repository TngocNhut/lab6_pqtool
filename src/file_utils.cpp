#include "pqtool/file_utils.hpp"

#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace pqtool {

std::vector<uint8_t> read_binary_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("cannot open input file: " + path);
    }

    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("cannot determine file size: " + path);
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));
    in.seekg(0, std::ios::beg);

    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw std::runtime_error("failed reading file: " + path);
        }
    }

    return data;
}

void write_binary_file(const std::string& path, const std::vector<uint8_t>& data) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + path);
    }

    if (!data.empty()) {
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out) {
            throw std::runtime_error("failed writing file: " + path);
        }
    }
}

void write_text_file(const std::string& path, const std::string& data) {
    const std::filesystem::path p(path);
    if (!p.parent_path().empty()) {
        std::filesystem::create_directories(p.parent_path());
    }

    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot open output file: " + path);
    }

    out << data;
}

bool file_exists(const std::string& path) {
    return std::filesystem::exists(path);
}

std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t max_bytes) {
    std::ostringstream oss;
    const size_t n = std::min(data.size(), max_bytes);

    for (size_t i = 0; i < n; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }

    if (data.size() > max_bytes) {
        oss << "...";
    }

    return oss.str();
}

} // namespace pqtool
