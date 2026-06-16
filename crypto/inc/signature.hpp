#pragma once

#include "rsa.hpp"
#include "sha256.hpp"
#include "serializers.hpp"

class Signer{
private:
    rsa::key_t priv;

public:

    Signer(rsa::key_t key);

    std::string sign(std::string str);
};

class Verifier {
private:
    rsa::key_t pub;

public:

    Verifier(rsa::key_t key);

    bool verify(std::string signature, std::string original);
};
