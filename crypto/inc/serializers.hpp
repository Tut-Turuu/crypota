#pragma once

#include <string>
#include <gmp.h>
#include <gmpxx.h>


mpz_class serialize_string(std::string str);
std::string serialize_to_string(mpz_class num);