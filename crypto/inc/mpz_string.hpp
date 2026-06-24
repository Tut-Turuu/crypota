#pragma once

#include <string>
#include <gmp.h>
#include <gmpxx.h>


mpz_class string_to_mpz(const std::string& str);
std::string mpz_to_string(const mpz_class& num);