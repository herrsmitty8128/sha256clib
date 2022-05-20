
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include <stdio.h>
#include <string.h>
#include <byteswap.h>
#include "sha256.h"

// this software is intended for little endian machines only
#if __BYTE_ORDER != __LITTLE_ENDIAN
#error Can not compile sha256 library. This is not a little endian machine.
#endif

/// Initialize hash value constants: The first 32 bits of the fractional parts of the square roots of the first 8 primes 2 through 19.
#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19

/// Initializes an array of constants: The first 32 bits of the fractional parts of the cube roots of the first 64 primes 2 through 311.
const uint32_t constants[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/// rotate a 32-bit integer right by n bits
#define ROR32(N,BITS) ((N >> BITS)|(N << (32 - BITS)))

/**
 * @brief Prints a sha-256 digest to stdio in hexidecimal format.
 * 
 * @param digest A pointer to an array of 8 32-bit unsigned words containing the digest to be printed.
 */
void printDigestAsHex(uint32_t* digest){
    for(int i = 0; i < 8; i++){
        uint32_t d = digest[i];
        printf("%08x", d);
    }
}

/**
 * @brief Converts a binary sha-256 digest into a null terimated string in hexidecimal format.
 * 
 * @param digest A poniter to an array of 8 32-bit unsigned words containing the digest to be converted.
 * @param str A pointer to the character buffer where the string will be written. This buffer must be at least 65 bytes long.
 */
void digest2Hex(uint32_t* digest, char* str){
    char temp[9] = {0};
    str[0] = '\0';
    for(int i = 0; i < 8; i++){
        sprintf(&temp[0], "%08x", digest[i]);
        strncat(str, &temp[0], 8);
    }
}

/**
 * @brief Converts a sha-256 digest from hexidecimal string format to binary format.
 * 
 * @param str A pointer to a 65 byte null terminated character buffer ("string") containing a sha-256 digest in hexidecimal format.
 * @param digest A poniter to an array of 8, 32-bit unsigned words where the digest will be written.
 */
void hex2Digest(char* str, uint32_t* digest){
    char hexstring[9];
    for(int i = 0; i < 8; i++){
        memcpy(&hexstring[0], &str[i * 8], 8);
        hexstring[8] = '\0';
        digest[i] = (uint32_t)strtol(hexstring, NULL, 16);
    }
}

/**
 * @brief Compares two sha-256 digests for equality.
 * 
 * @param digest1 The first digest to compare.
 * @param digest2 The second digest to compare.
 * @return true if the digests are the same.
 * @return false if the digests are not the same.
 */
bool digestsAreEqual(uint32_t* digest1, uint32_t* digest2){
    for(int i = 0; i < 8; i++){
        if(digest1[i] != digest2[i]) return false;
    }
    return true;
}

/**
 * @brief Calculates a sha-256 hash digest from data in 'buffer' and writes it to 'digest'.
 * 
 * @param buffer A buffer containing the data to be hashed.
 * @param byteCount The number of bytes in the buffer.
 * @param digest A pointer to an array of 8, 32-bit unsigned words where the digest will be written.
 * @return Returns true on success or false on failure.
 */
bool calcSHA256(uint8_t* buffer, size_t byteCount, uint32_t* digest){

    uint64_t  originalBitCount, bitCount;
    uint64_t* buffTail;
    uint8_t*  newBuffer;
    uint32_t* chunk;
    uint32_t  a, b, c, d, e, f, g, h;
    uint32_t  msg_schedule[64];
    uint32_t  w0, w1, w9, w14;
    uint32_t  sigma0, sigma1, choice, majority, temp1, temp2;

    // calculate the total number of bits in the buffer
    originalBitCount = byteCount * 8;

    // add 1 bit and 64 bits
    bitCount = originalBitCount + 1 + 64;

    // round to nearest multiple of 512 bits
    bitCount += 512 - (bitCount & 511);

    // create a new buffer
    newBuffer = (uint8_t*)calloc(bitCount / 8, 1);
    if(newBuffer == NULL) return false;

    // copy the old buffer's data into the new buffer
    memcpy(newBuffer, buffer, byteCount);

    // append a single "1"
    newBuffer[byteCount] = 128;

    // Append 64 bits to the end, where the 64 bits are a big-endian
    // integer representing the length of the original input in binary.
    buffTail = (uint64_t*)(&newBuffer[((bitCount - 64) / 8)]);
    *buffTail = __bswap_64(originalBitCount);

    // initialize the digest with the hash value constants
    digest[0] = H0;
    digest[1] = H1;
    digest[2] = H2;
    digest[3] = H3;
    digest[4] = H4;
    digest[5] = H5;
    digest[6] = H6;
    digest[7] = H7;

    // break the message block into 512-bit chunks. This is the "chunk loop"
    for(size_t ck = 0, chuckCount = bitCount / 512; ck < chuckCount; ck++){

        // calculate the offset, in bytes, of the next chunk. there are 64 byes in one chunk.
        chunk = (uint32_t*)(&newBuffer[ck * 64]); 

        // copy 1st chunk into 1st 16 words w[0..15] of the message schedule array
        // big-endian convention is used when parsing message block data from bytes to words
        for(int i = 0; i < 16; i++) msg_schedule[i] = __bswap_32(chunk[i]);
        
        // zero the rest of the message schedule
        //for(int i = 16; i < 64; i++) msg_schedule[i] = 0;

        // extend the first 16 words into the remaining 48 words of the message schedule
        for(int i = 0; i < 48; i++){
            w0  = msg_schedule[i];
            w1  = msg_schedule[i + 1];
            w1  = ROR32(w1,7) ^ ROR32(w1,18) ^ (w1 >> 3);
            w9  = msg_schedule[i + 9];
            w14 = msg_schedule[i + 14];
            w14 = ROR32(w14,17) ^ ROR32(w14,19) ^ (w14 >> 10);
            msg_schedule[i + 16] = w0 + w1 + w9 + w14;
        }

        // set the working variables to the hash values
        a = digest[0];
        b = digest[1];
        c = digest[2];
        d = digest[3];
        e = digest[4];
        f = digest[5];
        g = digest[6];
        h = digest[7];

        // the "compression loop"
        for(int i = 0; i < 64; i++){
            sigma0 = ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22);
            sigma1 = ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25);
            choice = (e & f) ^ ((~e) & g);
            majority = (a & b) ^ (a & c) ^ (b & c);
            temp1 = h + sigma1 + choice + constants[i] + msg_schedule[i];
            temp2 = sigma0 + majority;
            // update working variables
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // add the working variables to the digest
        digest[0] += a;
        digest[1] += b;
        digest[2] += c;
        digest[3] += d;
        digest[4] += e;
        digest[5] += f;
        digest[6] += g;
        digest[7] += h;
    }

    free(newBuffer);
    return true;
}
