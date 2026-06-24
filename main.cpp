#include <iostream>
#include "primes_and_pow.hpp"
#include <asio.hpp>
#include "rsa.hpp"
#include "serializers.hpp"
#include <string>

#define BITS 1024

using asio::ip::tcp;

int main() {


    rsa::RSA serv;

    auto priv = serv.share_my_private_key();
    auto pub = serv.share_my_public_key();

    rsa::store_key("keys/server/pub.key", pub);
    rsa::store_key("keys/server/priv.key", priv);

    auto loaded_priv = rsa::load_key("keys/server/priv.key");
    auto loaded_pub = rsa::load_key("keys/server/pub.key");
    std::cout << serialize_to_string(rsa::decrypt_message(rsa::encrypt_message(serialize_string("jopa"), pub), loaded_priv)) << "\n";

    return 0;
}
