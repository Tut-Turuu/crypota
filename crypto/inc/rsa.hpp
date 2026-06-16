#pragma once


#include <vector>
#include <gmp.h>
#include <gmpxx.h>


namespace rsa {
    struct key_t {
        mpz_class exp;
        mpz_class mod;
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
        RSA(unsigned bits_size);

        key_t share_my_public_key();
        key_t share_my_private_key();

	};

    key_t load_key(std::string filename);
    void store_key(std::string filename, const key_t& key);
}