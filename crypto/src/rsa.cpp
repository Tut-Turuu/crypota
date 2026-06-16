#include <vector>
#include "primes_and_pow.hpp"
#include "rsa.hpp"
#include "serializers.hpp"
#include <fstream>
#include <filesystem>
#include <iostream>

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

    RSA::RSA(unsigned bits_size) {
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



    namespace fs = std::filesystem;

    // Вспомогательная функция для создания директорий
    void ensure_directory_exists(const std::string& filepath) {
        fs::path path(filepath);
        fs::path parent = path.parent_path();
        
        if (!parent.empty() && !fs::exists(parent)) {
            if (!fs::create_directories(parent)) {
                throw std::runtime_error("Failed to create directory: " + parent.string());
            }
        }
    }

    void store_key(std::string filename, const key_t& key) {
        // Создаем директории, если их нет
        ensure_directory_exists(filename);
        
        std::ofstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file for writing: " + filename);
        }
        
        // Serialize exp and mod
        std::string exp_str = serialize_to_string(key.exp);
        std::string mod_str = serialize_to_string(key.mod);
        
        // Write lengths first, then the data
        size_t exp_len = exp_str.size();
        size_t mod_len = mod_str.size();
        
        file.write(reinterpret_cast<const char*>(&exp_len), sizeof(exp_len));
        file.write(exp_str.c_str(), exp_len);
        
        file.write(reinterpret_cast<const char*>(&mod_len), sizeof(mod_len));
        file.write(mod_str.c_str(), mod_len);
        
        file.close();
    }

    key_t load_key(std::string filename) {
        // Проверяем, существует ли файл
        if (!fs::exists(filename)) {
            throw std::runtime_error("File does not exist: " + filename);
        }
        
        std::ifstream file(filename, std::ios::binary);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open file for reading: " + filename);
        }
        
        key_t key;
        
        // Read length and data for exp
        size_t exp_len;
        file.read(reinterpret_cast<char*>(&exp_len), sizeof(exp_len));
        if (!file.good()) {
            throw std::runtime_error("Failed to read exp length from file");
        }
        
        std::string exp_str(exp_len, '\0');
        file.read(&exp_str[0], exp_len);
        if (!file.good()) {
            throw std::runtime_error("Failed to read exp data from file");
        }
        key.exp = serialize_string(exp_str);
        
        // Read length and data for mod
        size_t mod_len;
        file.read(reinterpret_cast<char*>(&mod_len), sizeof(mod_len));
        if (!file.good()) {
            throw std::runtime_error("Failed to read mod length from file");
        }
        
        std::string mod_str(mod_len, '\0');
        file.read(&mod_str[0], mod_len);
        if (!file.good()) {
            throw std::runtime_error("Failed to read mod data from file");
        }
        key.mod = serialize_string(mod_str);
        
        file.close();
        return key;
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
