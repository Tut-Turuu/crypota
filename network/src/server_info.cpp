#include <string>
#include "rsa.hpp"

std::string get_server_addr() {
    return "127.0.0.1";
}

int get_server_port() {
    return 5000;
}

rsa::key_t get_server_pub() {
    return rsa::load_key("./keys/server/pub.key");
}


