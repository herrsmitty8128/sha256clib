# sha256clib

## Description

*sha256clib* is a library of functions writting in C to calculate and manipulate SHA-256 digests. It includes functions to perform each of the following actions:

* Printing a digest to stdio in hexidecimal format.
* Converting a digest to a null terminated string in hexidecimal format.
* Converting a null terminated string in hexidecimal format to a digest in binary format.
* Comparing two binary digests for equality.
* Calculating a sha-256 digest from a data buffer.

## License

*sha256clib* is licensed under the Boost Software License - Version 1.0 - August 17th, 2003.

## Interface

void printDigestAsHex(uint32_t* digest);

void digest2Hex(uint32_t* digest, char* str);

void hex2Digest(char* str, uint32_t* digest);

bool digestsAreEqual(uint32_t* digest1, uint32_t* digest2);

bool calcSHA256(uint8_t* buffer, size_t byteCount, uint32_t* digest);
