#include "rsa.hpp"
#include "sha256.hpp"
#include "signature.hpp"
#include "mpz_string.hpp"


Signer::Signer(const rsa::key_t& key): priv(key) {}

std::string Signer::sign(const std::string& str) {
    std::string hash = sha256(str);
    return mpz_to_string(rsa::encrypt_message(string_to_mpz(hash), priv));
}


 Verifier::Verifier(const rsa::key_t& key): pub(key) {}

bool Verifier::verify(const std::string& signature, const std::string& original) {
    std::string hash = sha256(original);
    std::string res = mpz_to_string(rsa::decrypt_message(string_to_mpz(signature), pub));
    return hash == res;
}



// int main() {
//     rsa::RSA rsa_alg(1024);

//     Signer signer(rsa_alg.share_my_private_key());
//     std::string str("sex");
//     std::string signature = signer.sign(str);
//     Verifier verifier(rsa_alg.share_my_public_key());
//     std::cout << verifier.verify(signature, str) << "\n";

// }