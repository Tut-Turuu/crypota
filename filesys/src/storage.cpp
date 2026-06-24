#include <filesystem>
#include <fstream>
#include <string>
#include "storage.hpp"
#include "utils.hpp"


namespace fs = std::filesystem;

void ensure_directory_exists(const std::string& filepath) {
    fs::path path(filepath);
    fs::path parent = path.parent_path();
    
    if (!parent.empty() && !fs::exists(parent)) {
        if (!fs::create_directories(parent)) {
            throw std::runtime_error("Failed to create directory: " + parent.string());
        }
    }
}


void store_string(std::string filename, std::string data) {
    ensure_directory_exists(filename);
    
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for writing: " + filename);
    }
    
   
    file.write(data.c_str(), data.size());
    file.close();
}

std::string load_string(std::string filename) {
    if (!fs::exists(filename)) {
        throw std::runtime_error("File does not exist: " + filename);
    }
    
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file for reading: " + filename);
    }
    
    std::string data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    return data;
}


bool get_my_id_from_fs(int& id) {
    try {
        std::string str = load_string("self/id");
        if (str.size() != 4) return false;
        id = utils::string_to_number(str);
        return true;
    } catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool store_my_id(const int id) {
    try {
        std::string str_id = utils::number_to_string(id);
        store_string("self/id",str_id);
        return true;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool get_my_pub_from_fs(rsa::key_t& pub) {
    try {
        pub = rsa::load_key("self/pub.key");
        return true;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool get_my_priv_from_fs(rsa::key_t& priv) {
    try {
        priv = rsa::load_key("self/priv.key");
        return true;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool get_pub_by_id_from_fs(rsa::key_t& pub, const int id) {
    try {
        // std::cout << std::to_string(id) + "/pub.key" << std::endl;
        pub = rsa::load_key(std::to_string(id) + "/pub.key");
        
        return true;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool store_pub_by_id(const rsa::key_t& pub, const int id) {
    try {
        rsa::store_key(std::to_string(id) + "/pub.key", pub);
        return true;

    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}

bool get_sym_by_id_from_fs(aes::key_t& sym, int id) {
    try {
        sym = aes::load_key(std::to_string(id) + "/sym.key");
        return true;
    } catch (const std::exception& e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    catch (...) {
        std::cout << "unkown" << std::endl;
        return false;
    }
}
