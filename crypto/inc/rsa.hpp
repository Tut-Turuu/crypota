#pragma once


#include <vector>
#include <gmp.h>
#include <gmpxx.h>


namespace rsa {
    struct key_t {
        mpz_class exp;
        mpz_class mod;

        key_t();

        key_t(const key_t& other);

        key_t(const mpz_class& e, const mpz_class& m);

        bool operator==(const key_t& other) const;


    };

	void ext_euclidean_algorithm(const mpz_class& a, const mpz_class& b, mpz_class& x, mpz_class& y, mpz_class& gcd);

    mpz_class encrypt_message(mpz_class message, key_t key);
    mpz_class decrypt_message(mpz_class message, key_t key);

	class RSA {
    private:
        mpz_class n;
        mpz_class fi_n;
        mpz_class e;
        mpz_class d;

    public:
        RSA();

        key_t share_my_public_key();
        key_t share_my_private_key();

	};

    key_t deserialize_string_to_key(const std::string& data);
    std::string serialize_key_to_string(const key_t& key);

    key_t load_key(std::string filename);
    void store_key(std::string filename, const key_t& key);
}

namespace std {
    template <>
    struct hash<rsa::key_t> {
        size_t operator()(const rsa::key_t key) const;
    };
};