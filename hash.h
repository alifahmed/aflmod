/*
   american fuzzy lop - hashing function
   -------------------------------------

   The hash32() function is a variant of MurmurHash3, a good
   non-cryptosafe hashing function developed by Austin Appleby.

   For simplicity, this variant does *NOT* accept buffer lengths
   that are not divisible by 8 bytes. The 32-bit version is otherwise
   similar to the original; the 64-bit one is a custom hack with
   mostly-unproven properties.

   Austin's original code is public domain.

   Other code written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"

#ifdef __x86_64__

#include <immintrin.h>
extern u32 saved_hash;
static inline u32 hash32(const void* key, u32 len, u32 seed) {
	if(saved_hash) return saved_hash;
    u64 crc = seed;
    u64 crcCurr = seed;
    
    const u64* data = (u64*)key;
    
    len >>= 3;
    
    for(u32 i = 0; i < len; i++){
        crcCurr = _mm_crc32_u64(data[i], crcCurr);
        if(data[i]){
            crc = crcCurr;
        }
    }
    saved_hash = crc;
    return crc;
}

#else 

#define ROL32(_x, _r)  ((((u32)(_x)) << (_r)) | (((u32)(_x)) >> (32 - (_r))))

static inline u32 hash32(const void* key, u32 len, u32 seed) {

  const u32* data  = (u32*)key;
  u32 h1 = seed ^ len;

  len >>= 2;

  while (len--) {

    u32 k1 = *data++;

    k1 *= 0xcc9e2d51;
    k1  = ROL32(k1, 15);
    k1 *= 0x1b873593;

    h1 ^= k1;
    h1  = ROL32(h1, 13);
    h1  = h1 * 5 + 0xe6546b64;

  }

  h1 ^= h1 >> 16;
  h1 *= 0x85ebca6b;
  h1 ^= h1 >> 13;
  h1 *= 0xc2b2ae35;
  h1 ^= h1 >> 16;

  return h1;

}

#endif /* ^__x86_64__ */

#endif /* !_HAVE_HASH_H */
