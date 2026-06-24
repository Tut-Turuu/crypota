#include <vector>
#include <fstream>
#include <filesystem>
#include <iostream>
#include "primes_and_pow.hpp"
#include "rsa.hpp"
#include "mpz_string.hpp"
#include "storage.hpp"

#define BITS 1024

namespace rsa {

    void ext_euclidean_algorithm(const mpz_class& a, const mpz_class& b, mpz_class& x, mpz_class& y, mpz_class& gcd) {
        mpz_class r0, r1, r2;
        mpz_class x0, x1, x2;
        mpz_class y0, y1, y2;
        mpz_class q;

        if (a > b) {
            r0 = a;
            r1 = b;
        }
        else {
            r1 = a;
            r0 = b;
        }

        x0 = 1;
        x1 = 0;
        y0 = 0;
        y1 = 1;

        while (r1 != 0) {
            q = r0 / r1;
            r2 = r0 - q * r1;
            x2 = x0 - q * x1;
            y2 = y0 - q * y1;

            r0 = r1;
            r1 = r2;
            x0 = x1;
            x1 = x2;
            y0 = y1;
            y1 = y2;

        }
        gcd = r0;

        if (a > b) {
            x = x0;
            y = y0;
        }
        else {
            x = y0;
            y = x0;
        }

    }

    mpz_class encrypt_message(mpz_class message, key_t key) {
        return pow_by_mod(message, key.exp, key.mod);
    }

    mpz_class decrypt_message(mpz_class message, key_t key) {
        return pow_by_mod(message, key.exp, key.mod);
    }

    RSA::RSA() {
        unsigned bits_size = BITS;
        mpz_class p = generate_prime(bits_size);
        mpz_class q = generate_prime(bits_size);
        while (p == q)
            q = generate_prime(bits_size);

        n = p * q;
        fi_n = (p - 1) * (q - 1);

        e = 65537; // generate_prime(bits_size / 2);
        mpz_class k;
        mpz_class gcd;

        ext_euclidean_algorithm(e, fi_n, d, k, gcd);

        if (d < 0) {
            d = d % (fi_n)+(fi_n);
        }
    }

    key_t RSA::share_my_public_key() {
        return {e, n};
    }

    key_t RSA::share_my_private_key() {
        return {d, n};
    }




    std::string serialize_key_to_string(const key_t& key) {
        std::string exp_str = mpz_to_string(key.exp);
        std::string mod_str = mpz_to_string(key.mod);
        
        std::string result;
        size_t exp_len = exp_str.size();
        size_t mod_len = mod_str.size();
        
        result.append(reinterpret_cast<const char*>(&exp_len), sizeof(exp_len));
        result.append(exp_str);
        result.append(reinterpret_cast<const char*>(&mod_len), sizeof(mod_len));
        result.append(mod_str);
        
        return result;
    }

    key_t deserialize_string_to_key(const std::string& data) {
        key_t key;
        size_t offset = 0;
        
        size_t exp_len;
        memcpy(&exp_len, data.data() + offset, sizeof(exp_len));
        offset += sizeof(exp_len);
        
        std::string exp_str = data.substr(offset, exp_len);
        offset += exp_len;
        key.exp = string_to_mpz(exp_str);
        
        size_t mod_len;
        memcpy(&mod_len, data.data() + offset, sizeof(mod_len));
        offset += sizeof(mod_len);
        
        std::string mod_str = data.substr(offset, mod_len);
        key.mod = string_to_mpz(mod_str);
        
        return key;
    }

    void store_key(std::string filename, const key_t& key) {
        store_string(filename, serialize_key_to_string(key));
    }

    key_t load_key(std::string filename) {
        return deserialize_string_to_key(load_string(filename));
    }

}

// #include <iostream>
// using namespace rsa;

// int main() {
//     User u(1024);

//     auto priv = u.share_my_private_key();
//     auto publ = u.share_my_public_key();
//     std::cout << priv[0] << "\n\n" << publ[0] << "\n\n" << publ[1] << "\n\n";
//     mpz_class message = 123;
//     auto enc = encrypt_message(message, publ[0], publ[1]);
//     auto dec = u.decrypt_message(enc);
//     std::cout << dec << "\n\n";
// }
