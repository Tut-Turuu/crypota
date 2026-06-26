#include <iostream>
#include "crypto/inc/sha256.hpp"



int main() {
    auto hash = sha256("random string real bro");
    std::cout << hash.size() << std::endl;
}