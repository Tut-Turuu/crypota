#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <algorithm>
#include <gmp.h>
#include <gmpxx.h>
#include "primes_and_pow.hpp"
#include "diffie-hellman.hpp"


namespace dh {
    // Поиск первообразного корня (примитивного корня) по модулю p
    mpz_class find_primitive_root(mpz_class p) {
        // значение функции эйлера от простого числа на 1 меньше самого числа
        mpz_class phi = p - 1;

        std::vector<mpz_class> factors;

        mpz_class n = phi;
        for (mpz_class i = 2; i <= sqrt(n); i++) {
            if (n % i == 0) {
                factors.push_back(i);
                while (n % i == 0)
                    n /= i;
            }
        }
        if (n > 1)
            factors.push_back(n);

        // Проверка кандидатов
        for (mpz_class g = 2; g <= p; g++) {
            bool flag = true;
            for (auto f : factors) {
                if (pow_by_mod(g, phi / f, p) == 1) {
                    flag = false;
                    break;
                }
            }
            if (flag) return g;
        }
        return 0; // не должно случиться для простого p
    }

    User::User(mpz_class p, mpz_class g) : prime(p), generator(g) {
        generate_keys();
    }

    User::User(unsigned prime_bits) {
        prime = generate_prime(prime_bits);
        generator = 7;
        generate_keys();
    }

    void User::generate_keys() {
        gmp_randclass rng(gmp_randinit_default);
        rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

        private_key = (rng.get_z_range(prime - 4) + 2);
        public_key = pow_by_mod(generator, private_key, prime);
    }

    mpz_class User::get_public_key() const {
        return public_key;
    }

    mpz_class User::get_prime() const {
        return prime;
    }

    mpz_class User::get_generator() const {
        return generator;
    }

    mpz_class User::compute_shared_secret(mpz_class other_public_key) const {
        return pow_by_mod(other_public_key, private_key, prime);
    }
}