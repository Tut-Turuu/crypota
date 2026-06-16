#include <string>
#include <random>

std::string get_random_str(const unsigned int len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    

    std::string result;
    result.reserve(len);
    
    for (int i = 0; i < len; ++i) {
        result += dis(gen);
    }
    return result;
}