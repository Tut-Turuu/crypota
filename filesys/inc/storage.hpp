#pragma once
#include <string>
#include "rsa.hpp"
#include "aes.hpp"

void ensure_directory_exists(const std::string& filepath);

void store_string(std::string filename, std::string data);

std::string load_string(std::string filename);

bool get_server_pub(rsa::key_t& pub);

bool get_server_priv(rsa::key_t& priv); // only for server

bool get_my_id_from_fs(int& id);

bool store_my_id(const int id);

bool get_my_pub_from_fs(rsa::key_t& pub);

bool get_my_priv_from_fs(rsa::key_t& priv);

bool store_my_pub(const rsa::key_t& pub);

bool store_my_priv(const rsa::key_t& priv);

bool get_pub_by_id_from_fs(rsa::key_t& pub, int id);

bool store_pub_by_id(const rsa::key_t& pub, const int id);

bool get_sym_by_id_from_fs(aes::key_t& sym, int id);
