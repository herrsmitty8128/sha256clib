
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#ifndef _SHA_256_C_LIBRARY_
#define _SHA_256_C_LIBRARY_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void printDigestAsHex(uint32_t* digest);
void digest2Hex(uint32_t* digest, char* str);
void hex2Digest(char* str, uint32_t* digest);
bool digestsAreEqual(uint32_t* digest1, uint32_t* digest2);
bool calcSHA256(uint8_t* buffer, size_t byteCount, uint32_t* digest);

#ifdef __cplusplus
}
#endif

#endif