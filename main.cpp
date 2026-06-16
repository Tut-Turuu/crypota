#include <iostream>
#include "primes_and_pow.hpp"
// #include "diffie-hellman.hpp"
// #include "aes.hpp"
#include "rsa.hpp"
#include "serializers.hpp"

#define BITS 1024


int main() {
    rsa::RSA serv(BITS);

    auto priv = serv.share_my_private_key();
    auto pub = serv.share_my_public_key();

    rsa::store_key("/home/lalo/Desktop/crypota/keys/server/pub.key", pub);
    rsa::store_key("/home/lalo/Desktop/crypota/keys/server/priv.key", priv);

    auto loaded_priv = rsa::load_key("/home/lalo/Desktop/crypota/keys/server/priv.key");
    auto loaded_pub = rsa::load_key("/home/lalo/Desktop/crypota/keys/server/pub.key");
    std::cout << serialize_to_string(rsa::decrypt_message(rsa::encrypt_message(serialize_string("jopa"), pub), loaded_priv)) << "\n";

    return 0;
}
