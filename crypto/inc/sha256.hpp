#pragma once

#include <iostream>
#include <cstring>
#include <vector>
#include <arpa/inet.h>



typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;


inline u8 get_sym(u8 num);

void read_hex(u8* block, u32 n);

u32 rotr(u32 x, u32 n);

u32 rotl(u32 x, u32 n);

u32 ch(u32 x, u32 y, u32 z);

u32 maj(u32 x, u32 y, u32 z);

u32 SIG0(u32 x);

u32 SIG1(u32 x);

u32 sig0(u32 x);

u32 sig1(u32 x);

u32 get_padded_sz(u32 sz);

void inv_endian64(u8* x);

void _sha256(const u8* in, u32 sz, u8* out);

std::string sha256(std::string str);
