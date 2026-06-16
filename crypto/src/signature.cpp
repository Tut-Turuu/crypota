#include "rsa.hpp"
#include "sha256.hpp"
#include "serializers.hpp"
#include "signature.hpp"


Signer::Signer(rsa::key_t key) {
    priv = key;
}

std::string Signer::sign(std::string str) {
    std::string hash = sha256(str);
    return serialize_to_string(rsa::encrypt_message(serialize_string(hash), priv));
}


Verifier::Verifier(rsa::key_t key) {
    pub = key;
}

bool Verifier::verify(std::string signature, std::string original) {
    std::string hash = sha256(original);
    std::string res = serialize_to_string(rsa::decrypt_message(serialize_string(signature), pub));
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