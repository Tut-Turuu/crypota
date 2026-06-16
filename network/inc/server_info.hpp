#pragma once

#include <string>
#include "rsa.hpp"

std::string get_server_addr();

int get_server_port();

rsa::key_t get_server_pub();



