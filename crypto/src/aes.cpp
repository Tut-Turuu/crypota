#include <iostream>
#include <bitset>
#include <cstring>
#include <vector>
#include "storage.hpp"

namespace aes {


    typedef unsigned char  u8;
    typedef unsigned short u16;
    typedef unsigned int   u32;


    static u8 rcon[] = {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x00,
        0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00,
        0x1b, 0x00, 0x00, 0x00,
        0x36, 0x00, 0x00, 0x00
    };

    static u8 sbox[] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    static u8 inv_sbox[] = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };


    void sub_word(u8* word32) {
        for (int i = 0; i < 4; ++i) {
            word32[i] = sbox[word32[i]];
        }
    }

    void rot_word(u8* word32) {
        u8 tmp = word32[0];
        word32[0] = word32[1];
        word32[1] = word32[2];
        word32[2] = word32[3];
        word32[3] = tmp;
    }

    // void xor(u8* a, const u8* b, int n) {

    // }

    void key_expansion(u8* key128, u8* word128x11) {
        u32 nb = 4; // counters in 4 bytes
        u32 nk = 4;
        u32 nr = 10;

        memcpy(word128x11, key128, 16);

        u32 i = nk;
        u32 temp;

        while (i < nb*(nr + 1)) {
            memcpy((u8*)&temp, word128x11 + ((i - 1)*4), 4);
            if (i % nk == 0) {
                rot_word((u8*)&temp);
                sub_word((u8*)&temp);
                temp ^= ((u32*)rcon)[i / nk - 1]; 
            }
            temp ^= ((u32*)word128x11)[i - nk];
            memcpy(word128x11 + i*4, &temp, 4);
            i += 1;
        }
    }

    u8 GF256_add(u8 a, u8 b) {
        return a ^ b;
    }

    u8 GF256_multiply(u8 a, u8 b) {
        // irreducible polynom: x^8 + x^4 + x^3 + x + 1
        u16 irreducible = 0x011b << 6;

        u16 tmp_a = a;
        u16 word = 0;
        u8 mask = 0x01;
        for (int i = 0; i < 8; ++i) {
            if (b & mask) {
                word ^= tmp_a;
            }
            tmp_a <<= 1;
            mask <<= 1;
        }
        u16 mask_s = 0x4000;
        for (int i = 0; i < 7; ++i) {
            if (word & mask_s) {
                word ^= irreducible;
            }
            irreducible >>= 1;
            mask_s >>= 1;
        }
        return (u8)word;
    }


    void sub_bytes(u8*   block128) {
        unsigned int tmp;
        for (int i = 0; i < 16; ++i) {
            block128[i] = sbox[block128[i]];
        }
    }

    void shift_rows(u8*  block128) {
        u8 tmp;

        tmp = block128[1];
        block128[1] = block128[5];
        block128[5] = block128[9];
        block128[9] = block128[13];
        block128[13] = tmp;

        tmp = block128[2];
        block128[2] = block128[10];
        block128[10] = tmp;
        tmp = block128[6];
        block128[6] = block128[14];
        block128[14] = tmp;

        tmp = block128[3];
        block128[3] = block128[15];
        block128[15] = block128[11];
        block128[11] = block128[7];
        block128[7] = tmp;

    }

    void mix_columns(u8* block128) {
        u8 c0 = 0, c1 = 0, c2 = 0, c3 = 0;
        for (int i = 0; i < 4; ++i) {

            
            c0 = GF256_multiply(block128[i*4], 0x02) ^ GF256_multiply(block128[i*4 + 1], 0x03) ^ block128[i*4 + 2] ^ block128[i*4 + 3];
            c1 = GF256_multiply(block128[i*4 + 1], 0x02) ^ GF256_multiply(block128[i*4 + 2], 0x03) ^ block128[i*4 + 3] ^ block128[i*4];
            c2 = GF256_multiply(block128[i*4 + 2], 0x02) ^ GF256_multiply(block128[i*4 + 3], 0x03) ^ block128[i*4 + 1] ^ block128[i*4];
            c3 = GF256_multiply(block128[i*4 + 3], 0x02) ^ GF256_multiply(block128[i*4], 0x03) ^ block128[i*4 + 2] ^ block128[i*4 + 1];
            block128[i*4] = c0;
            block128[i*4 + 1] = c1;
            block128[i*4 + 2] = c2;
            block128[i*4 + 3] = c3;

        }
    }

    void add_round_key(u8* block128, u8* round_key128) {
        for (int i = 0; i < 16; ++i) {
            block128[i] ^= round_key128[i];
        }
    }

    void inv_sub_bytes(u8*   block128) {
        unsigned int tmp;
        for (int i = 0; i < 16; ++i) {
            tmp = block128[i];
            block128[i] = inv_sbox[tmp];
        }
    }
    void inv_shift_rows(u8*  block128) {
        u8 tmp;

        tmp = block128[3];
        block128[3] = block128[7];
        block128[7] = block128[11];
        block128[11] = block128[15];
        block128[15] = tmp;

        tmp = block128[2];
        block128[2] = block128[10];
        block128[10] = tmp;
        tmp = block128[6];
        block128[6] = block128[14];
        block128[14] = tmp;

        tmp = block128[1];
        block128[1] = block128[13];
        block128[13] = block128[9];
        block128[9] = block128[5];
        block128[5] = tmp;
        
    }
    void inv_mix_columns(u8* block128) {
        u8 c0 = 0, c1 = 0, c2 = 0, c3 = 0;
        for (int i = 0; i < 4; ++i) {

            c0 = GF256_multiply(block128[i*4], 0x0e) ^ GF256_multiply(block128[i*4 + 1], 0x0b) ^ GF256_multiply(block128[i*4 + 2], 0x0d) ^ GF256_multiply(block128[i*4 + 3], 0x09);
            c1 = GF256_multiply(block128[i*4], 0x09) ^ GF256_multiply(block128[i*4 + 1], 0x0e) ^ GF256_multiply(block128[i*4 + 2], 0x0b) ^ GF256_multiply(block128[i*4 + 3], 0x0d);
            c2 = GF256_multiply(block128[i*4], 0x0d) ^ GF256_multiply(block128[i*4 + 1], 0x09) ^ GF256_multiply(block128[i*4 + 2], 0x0e) ^ GF256_multiply(block128[i*4 + 3], 0x0b);
            c3 = GF256_multiply(block128[i*4], 0x0b) ^ GF256_multiply(block128[i*4 + 1], 0x0d) ^ GF256_multiply(block128[i*4 + 2], 0x09) ^ GF256_multiply(block128[i*4 + 3], 0x0e);
            block128[i*4] = c0;
            block128[i*4 + 1] = c1;
            block128[i*4 + 2] = c2;
            block128[i*4 + 3] = c3;

        }
    }


    inline u8 get_sym(u8 num) {
        if (num >= 0 && num <= 9) {
            return num + '0';
        }
        if (num >= 10 && num <= 15) {
            return num - 10 + 'a';
        }
        return 'S';
    } 

    void read_hex(u8* block, int n) {

        for (int i = 0; i < n; ++i) {
            std::cout << get_sym((block[i] >> 4) & 0x0f) << get_sym(block[i] & 0x0f) << ' ';
        }
        std::cout << '\n';
    }


    void cipher128(u8* block128, u8* word128x11) {

        int rounds = 10;
        add_round_key(block128, word128x11);

        for (int i = 1; i < rounds; ++i) {
            sub_bytes(block128);
            shift_rows(block128);
            mix_columns(block128);
            add_round_key(block128, word128x11 + i*16);
        }
        sub_bytes(block128);
        shift_rows(block128);
        add_round_key(block128, word128x11 + rounds*16);
        
    }

    void invcipher128(u8* block128, u8* word128x11) {
        int rounds = 10;

        add_round_key(block128, word128x11 + rounds*16);
        inv_shift_rows(block128);
        inv_sub_bytes(block128);

        for (int i = 1; i < rounds; ++i) {
            add_round_key(block128, word128x11 + (rounds-i)*16);
            inv_mix_columns(block128);
            inv_shift_rows(block128);
            inv_sub_bytes(block128);
        }

        add_round_key(block128, word128x11);
    }

    int count_ones(u8* block, int n) {
        u8 tmp;
        int res = 0;
        for (int i = 0; i < n; ++i) {
            tmp = block[i];
            for (int j = 0; j < 7; ++j) {
                res += tmp & 0x01;
                tmp >>= 1;
            }
        }
        return res;
    }

    void key_gen(key_t& key) {
        for (int i = 0; i < 16; ++i) {
            key.key[i] = rand() % 256;
        }
    }


    Chipher::Chipher(key_t init_key) {
        memcpy(key.key, init_key.key, sizeof(key.key));
        key_expansion(init_key.key, expanded_key.word128x11);
    }

    std::string Chipher::encrypt_string(const std::string& str) {

        size_t len = str.length();
        size_t padded_len = ((len + 15) / 16) * 16;
        u8 padding = padded_len - len;
        
        std::vector<u8> data(padded_len);
        memcpy(data.data(), str.c_str(), len);
        for (size_t i = len; i < padded_len; i++) data[i] = 0;

        for (size_t i = 0; i < padded_len; i += 16) {
            cipher128(data.data() + i, expanded_key.word128x11);
        }
        
        return std::string(data.begin(), data.end());
    }

    std::string Chipher::decrypt_string(const std::string& str) {
        std::vector<u8> data(str.begin(), str.end());
        
        for (size_t i = 0; i < data.size(); i += 16) {
            invcipher128(data.data() + i, expanded_key.word128x11);
        }
        
        size_t original_len = data.size();
        while (original_len > 0 && data[original_len - 1] == 0) {
            original_len--;
        }
        data.resize(original_len);

        return std::string(data.begin(), data.end());
    
    };

    std::string serialize_key_to_string(const key_t& key) {
        return std::string(reinterpret_cast<const char*>(key.key), sizeof(key.key));
    }

    key_t deserialize_string_to_key(const std::string& str) {
        if (str.size() != 16) {
            throw std::runtime_error("Invalid key size: expected 16 bytes, got " + std::to_string(str.size()));
        }
        
        key_t result;
        memcpy(result.key, str.data(), 16);
        return result;
    }

    void store_key(const std::string& filename, const key_t& key) {
        store_string(filename, serialize_key_to_string(key));
    }

    key_t load_key(const std::string& filename) {
        return deserialize_string_to_key(load_string(filename));
    }

} 





// int main() {
//     // srand(time(0));
//     // u8 block[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//     // // u8 key[16] =   {0x12, 0x84, 0xf3, 0x1b, 0x88, 0x05, 0x90, 0x51, 0x77, 0x46, 0xac, 0xb2, 0x1c, 0xbd, 0xe4, 0xff};
//     aes::key_t key = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//     // u8 word128x11[16*11];
//     // key_gen(key, 16);
//     // key_expansion(key, word128x11);

//     // cipher128(block, word128x11);

//     // std::cout << "ciphered block:\n";
//     // read_hex(block, 16);
    
   
//     // invcipher128(block, word128x11);

//     // std::cout << "deciphered block:\n";
//     // read_hex(block, 16);

//     aes::Chipher chipher(key);
//     std::cout << chipher.decrypt_string(chipher.encrypt_string("dotka")) << "\n";
// }
