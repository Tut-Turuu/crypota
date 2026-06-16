#include <iostream>
#include <gmp.h>
#include <gmpxx.h>
#include <chrono>
#include "primes_and_pow.hpp"


# define TEST_ITERATIONS 20


// быстрое возведение в степень по модулю
mpz_class pow_by_mod(mpz_class base, mpz_class power, const mpz_class& mod) {
	mpz_class result = 1;
	base = base % mod;
	while (power > 0) {
		if ((power & 1) == 1)
			result = (result * base) % mod;
		base = (base * base) % mod;
		power >>= 1;
	}
	return result;
}


// проверка на простоту при помощи теста миллера-рабина
bool is_prime(const mpz_class& n) {
	if (n <= 1) return false;
	if (n <= 3) return true;
	if (n % 2 == 0) return false;

	// представляем n-1 в виде d * 2^s
	mpz_class q = n - 1;
	mpz_class s = 0;
	while (q % 2 == 0) {
		q /= 2;
		s++;
	}

	gmp_randclass rng(gmp_randinit_default);
	rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

	for (int i = 0; i < TEST_ITERATIONS; i++) {
		// случайное число в качестве основания
		mpz_class a = rng.get_z_range(n - 3) + 2;
		mpz_class x;
		mpz_powm(x.get_mpz_t(), a.get_mpz_t(), q.get_mpz_t(), n.get_mpz_t());

		if (x == 1 || x == n - 1) continue;

		bool composite = true;
		for (mpz_class j = 0; j < s - 1; j++) {
			mpz_powm_ui(x.get_mpz_t(), x.get_mpz_t(), 2, n.get_mpz_t());
			if (x == n - 1) {
				composite = false;
				break;
			}
		}
		if (composite) return false;
	}
	return true;
}


// Генерация случайного простого числа заданной битности
mpz_class generate_prime(const unsigned int bits) {
	gmp_randclass rng(gmp_randinit_default);
	rng.seed(std::chrono::system_clock::now().time_since_epoch().count());

	mpz_class potencial_prime;
	do {
		potencial_prime = rng.get_z_bits(bits);
		// гарантируемая битность
		mpz_setbit(potencial_prime.get_mpz_t(), bits - 1);
		// нечетность
		mpz_setbit(potencial_prime.get_mpz_t(), 0);
	} while (!is_prime(potencial_prime));

	return potencial_prime;
}
