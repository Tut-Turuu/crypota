#include <string>
#include <vector>
#include <cstdint>
#include <gmp.h>
#include <gmpxx.h>
#include "mpz_string.hpp"


mpz_class string_to_mpz(const std::string& str) {
    mpz_class result;
    
    if (str.empty()) {
        return result;
    }

    std::vector<uint8_t> bytes(str.begin(), str.end());
    
    mpz_import(result.get_mpz_t(), bytes.size(), 1, 1, 1, 0, bytes.data());
    
    return result;
}

std::string mpz_to_string(const mpz_class& num) {
    if (num == 0) {
        return "";
    }

    size_t size = mpz_sizeinbase(num.get_mpz_t(), 256);
    
    std::vector<uint8_t> bytes(size);
    
    mpz_export(bytes.data(), NULL, 1, 1, 1, 0, num.get_mpz_t());
    
    return std::string(bytes.begin(), bytes.end());
}