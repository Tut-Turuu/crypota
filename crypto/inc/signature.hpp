#pragma once

#include "rsa.hpp"
#include "sha256.hpp"

class Signer{
private:
    const rsa::key_t priv;

public:

    Signer(const rsa::key_t& key);

    std::string sign(const std::string& str);
};

class Verifier {
private:
    const rsa::key_t pub;

public:

    Verifier(const rsa::key_t& key);

    bool verify(const std::string& signature, const std::string& original);
};
