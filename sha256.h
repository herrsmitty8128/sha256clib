
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#ifndef _SHA_256_C_LIBRARY_
#define _SHA_256_C_LIBRARY_

// this software is intended for little endian machines only
#if __BYTE_ORDER != __LITTLE_ENDIAN
#error Can not compile sha256 library. This is not a little endian machine.
#endif

#ifdef __cplusplus
#include <cstdlib>
#include <cstdint>
#include <cstdbool>
#include <cstdio>
#include <cstring>
extern "C" {
#endif

#ifndef __cplusplus
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#endif

#include <byteswap.h>

void printDigestAsHex(uint32_t* digest);
void digestToHex(uint32_t* digest, char* str);
void hexToDigest(char* str, uint32_t* digest);
bool digestsAreEqual(uint32_t* digest1, uint32_t* digest2);
bool calcSHA256(uint8_t* buffer, size_t byteCount, uint32_t* digest);

#ifdef __cplusplus
};
#endif

#endif