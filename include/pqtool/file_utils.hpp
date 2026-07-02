#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pqtool {

std::vector<uint8_t> read_binary_file(const std::string& path);
void write_binary_file(const std::string& path, const std::vector<uint8_t>& data);
void write_text_file(const std::string& path, const std::string& data);
bool file_exists(const std::string& path);

std::string bytes_to_hex(const std::vector<uint8_t>& data, size_t max_bytes = 64);

} // namespace pqtool
