#include <iostream>
#include <cstring>
#include <vector>
#include <arpa/inet.h>
#include "sha256.hpp"




inline u8 get_sym(u8 num) {
    if (num >= 0 && num <= 9) {
        return num + '0';
    }
    if (num >= 10 && num <= 15) {
        return num - 10 + 'a';
    }
    return 'S';
} 

void read_hex(u8* block, u32 n) {

    for (u32 i = 0; i < n; ++i) {
        if (i % 4 == 0 && i != 0) std::cout << ' ';
        std::cout << get_sym((block[i] >> 4) & 0x0f) << get_sym(block[i] & 0x0f);
        
    }
    std::cout << '\n';
}

static const u32 K[64] {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

u32 rotr(u32 x, u32 n) {
    return ((x >> n) | (x << (32 - n)));
}

u32 rotl(u32 x, u32 n) {
    return ((x << n) | (x >> (32 - n)));
}

u32 ch(u32 x, u32 y, u32 z) {
    return (x & y) ^ (x & z);
}

u32 maj(u32 x, u32 y, u32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

u32 SIG0(u32 x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

u32 SIG1(u32 x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

u32 sig0(u32 x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

u32 sig1(u32 x) {
    return rotr(x,17) ^ rotr(x, 19) ^ (x >> 10);
}


u32 get_padded_sz(u32 sz) {
    u32 k = (960 - (sz*8 + 1) % 512) % 512;
    return (sz*8 + 1 + k + 64)/8;
}

void inv_endian64(u8* x) {
    u8 tmp;
    tmp = x[0];
    x[0] = x[7];
    x[7] = tmp;

    tmp = x[1];
    x[1] = x[6];
    x[6] = tmp;

    tmp = x[2];
    x[2] = x[5];
    x[5] = tmp;

    tmp = x[3];
    x[3] = x[4];
    x[4] = tmp;
}

void _sha256(const u8* in, u32 sz, u8* out) { 

    u32 padded_sz = get_padded_sz(sz);
    u32 N_blocks = padded_sz/64; // one block = 512 bits
    u32 k = (960 - (sz*8 + 1) % 512) % 512;
    u64 l = sz*8;
    inv_endian64((u8*)&l);

    u8* padded = new u8[padded_sz];
    memcpy(padded, in, sz);
    padded[sz] = 0x80;
    memset(padded + sz + 1, 0, padded_sz - sz - 9);
    memcpy(padded + padded_sz - 8, &l, 8);

    u32 a;
    u32 b;
    u32 c;
    u32 d;
    u32 e;
    u32 f;
    u32 g;
    u32 h;

    u32 T1;
    u32 T2;

    u32 h0 = 0x6a09e667;
    u32 h1 = 0xbb67ae85;
    u32 h2 = 0x3c6ef372;
    u32 h3 = 0xa54ff53a;
    u32 h4 = 0x510e527f;
    u32 h5 = 0x9b05688c;
    u32 h6 = 0x1f83d9ab;
    u32 h7 = 0x5be0cd19;

    u32 W[64];

    for (u32 i = 0; i < N_blocks; ++i) {
        memcpy((void*)W, padded + i*64, 64);
        for (u32 t = 16; t < 64; ++t) {
            W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
        }

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;
        
        for (u32 t = 0; t < 64; ++t) {
            T1 = h + SIG1(e) + ch(e,f,g) + K[t] + W[t];
            T2 = SIG0(a) + maj(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        h0 = a + h0;
        h1 = b + h1;
        h2 = c + h2;
        h3 = d + h3;
        h4 = e + h4;
        h5 = f + h5;
        h6 = g + h6;
        h7 = h + h7;
    }

    memcpy(out     , &h0, 4);
    memcpy(out + 4 , &h1, 4);
    memcpy(out + 8 , &h2, 4);
    memcpy(out + 12, &h3, 4);
    memcpy(out + 16, &h4, 4);
    memcpy(out + 20, &h5, 4);
    memcpy(out + 24, &h6, 4);
    memcpy(out + 28, &h7, 4);

    delete padded;

}

std::string sha256(std::string str) {
    std::vector<u8> res;
    res.resize(32);
    _sha256((u8*)str.data(), str.size(), res.data());
    return std::string(res.begin(), res.end());
}

// int main() {
//     const u8 msg[] = "a";

//     u8 out[32];
//     _sha256(msg, strlen((const char*)msg), out);

//     read_hex(out, 32);
// }