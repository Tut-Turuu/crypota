#pragma once
#include <string>
#include <cstdint>


namespace utils {
    std::string number_to_string(uint32_t num);
    
    uint32_t string_to_number(const std::string& data, size_t offset = 0);
}