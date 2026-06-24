#pragma once
#include <iostream>
#include <bitset>
#include <cstring>
#include <vector>

namespace aes {


    typedef unsigned char  u8;
    typedef unsigned short u16;
    typedef unsigned int   u32;


    void sub_word(u8* word32);

    void rot_word(u8* word32);

    void key_expansion(u8* key128, u8* word128x11);

    u8 GF256_add(u8 a, u8 b);

    u8 GF256_multiply(u8 a, u8 b);

    void sub_bytes(u8*   block128);

    void shift_rows(u8*  block128);

    void mix_columns(u8* block128);

    void add_round_key(u8* block128, u8* round_key128);

    void inv_sub_bytes(u8*   block128);

    void inv_shift_rows(u8*  block128);

    void inv_mix_columns(u8* block128);


    inline u8 get_sym(u8 num);

    void read_hex(u8* block, int n);

    void cipher128(u8* block128, u8* word128x11);

    void invcipher128(u8* block128, u8* word128x11);

    int count_ones(u8* block, int n);

    struct key_t {
        u8 key[16];
    };

    struct expanded_key_t {
        u8 word128x11[16*11];
    };

    void key_gen(key_t& key);



    class Chipher {
        private:
            key_t key;
            expanded_key_t expanded_key;
        public:
            Chipher(key_t init_key);

            std::string encrypt_string(const std::string& str);
            

            std::string decrypt_string(const std::string& str);

    };

    std::string serialize_key_to_string(const key_t& key);

    key_t deserialize_string_to_key(const std::string& str);

    void store_key(const std::string& filename, const key_t& key);

    key_t load_key(const std::string& filename);
} 

