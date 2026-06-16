# pragma once


namespace dh {

    mpz_class find_primitive_root(mpz_class p);

	class User {

    private:

        mpz_class prime;
        mpz_class generator;
        mpz_class private_key;
        mpz_class public_key;

    public:

        User(mpz_class p, mpz_class g);

        User(unsigned prime_bits);

        void generate_keys();

        mpz_class get_public_key() const;

        mpz_class get_prime() const;

        mpz_class get_generator() const;

        mpz_class compute_shared_secret(mpz_class other_public_key) const;
	};

}