#include <string>
#include <cstdint>
#include <stdexcept>

namespace utils {
    std::string number_to_string(uint32_t num) {
        std::string result(4, '\0');
        result[0] = (num >> 24) & 0xFF;
        result[1] = (num >> 16) & 0xFF;
        result[2] = (num >> 8) & 0xFF;
        result[3] = num & 0xFF;
        return result;
    }
    
    uint32_t string_to_number(const std::string& data, size_t offset = 0) {
        if (data.size() < offset + 4) {
            throw std::out_of_range("Not enough data");
        }
        return (static_cast<uint32_t>(static_cast<unsigned char>(data[offset])) << 24) |
               (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 1])) << 16) |
               (static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 2])) << 8) |
               static_cast<uint32_t>(static_cast<unsigned char>(data[offset + 3]));
    }
}