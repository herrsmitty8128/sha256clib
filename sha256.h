
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
#include <cstdint>
extern "C" {
#endif

#ifndef __cplusplus
#include <stdint.h>
#include <stdbool.h>
#endif

/**
 * @brief Prints a binary sha-256 digest to stdio in hexidecimal format.
 * 
 * @param digest A pointer to an array of 8 32-bit unsigned words containing the digest to be printed.
 */
void printDigestAsHex(uint32_t* digest);

/**
 * @brief Converts a binary sha-256 digest into a null terimated string in hexidecimal format.
 * 
 * @param digest A poniter to an array of 8 32-bit unsigned words containing the digest to be converted.
 * @param str A pointer to the character buffer where the string will be written. This buffer must be at least 65 bytes long.
 */
void digestToHex(uint32_t* digest, char* str);

/**
 * @brief Converts a sha-256 digest from hexidecimal string format to binary format.
 * 
 * @param str A pointer to a 65 byte null terminated character buffer ("string") containing a sha-256 digest in hexidecimal format.
 * @param digest A poniter to an array of 8, 32-bit unsigned words where the digest will be written.
 */
void hexToDigest(char* str, uint32_t* digest);

/**
 * @brief Compares two binary sha-256 digests for equality.
 * 
 * @param digest1 The first digest to compare.
 * @param digest2 The second digest to compare.
 * @return true if the digests are the same.
 * @return false if the digests are not the same.
 */
bool digestsAreEqual(uint32_t* digest1, uint32_t* digest2);

/**
 * @brief Calculates a sha-256 hash digest from data in 'buffer' and writes it to 'digest'.
 * 
 * @param buffer A pointer to a buffer containing the data to be hashed.
 * @param byteCount The number of bytes in the buffer.
 * @param digest A pointer to an array of 8, 32-bit unsigned words where the digest will be written.
 * @return true if the calculation completed successfully
 * @return false if the calculation did not complete successfully
 */
bool calcSHA256(uint8_t* buffer, uint64_t byteCount, uint32_t* digest);

#ifdef __cplusplus
};
#endif

#endif