# sha256clib

*sha256clib* is a library of functions written in C to calculate and manipulate SHA-256 digests. It includes the following:

| Function | Description |
|----------|-------------|
|void sha256_printDigestAsHex(uint32_t* digest);|Prints a binary sha-256 digest to stdio in hexidecimal format.|
|void sha256_digestToHex(uint32_t* digest, char* str);|Converts a binary sha-256 digest into a null terimated string in hexidecimal format.|
|void sha256_hexToDigest(char* str, uint32_t* digest);|Converts a sha-256 digest from a null terminated hexidecimal string into binary format.|
|bool sha256_digestsAreEqual(uint32_t* digest1, uint32_t* digest2);|Compares two binary sha-256 digests for equality.|
|bool sha256_binToDigest(uint8_t* buffer, size_t byteCount, uint32_t* digest);|Calculates a sha-256 digest from data in *buffer* and writes it to *digest*.|
|bool sha256_fileToDigest(FILE* f, uint32_t* digest);|Calculates a sha-256 hash digest from a file and writes it to *digest*.|

## Notes

Please note the following before attempting to use *sha256clib* :

* *sha256clib* was not designed or tested for muliprocessing.
* *sha256clib* was designed for use and tested on *little-endian* machines only.
* A sha-256 digest is always an array of 8 32-bit integers (for example, *uint32_t digest[8];*)
* The null terminated hexidecimal string representation of a sha-256 digest is always an array of 64 bytes terminated by an additional null character, for a total of 65 bytes.

## Building and Running

The accompanying *makefile* is designed to build a shared library on Linux. You can modify the location of the shared library by changing the *libpath* variable on the second line of the *makefile*. It also generates an executable called *calcsha256*, which calculates a digest from a file path provided as a command line argument similar to *sha256sum*.

## License

*sha256clib* is licensed under the Boost Software License - Version 1.0 - August 17th, 2003.

## Resources

The following are suggested resources for anyone interested in understanding how the sha-256 algorithm works.\:

* https://sha256algorithm.com/
* https://blog.boot.dev/cryptography/how-sha-2-works-step-by-step-sha-256/
* https://medium.com/a-42-journey/implementing-the-sha256-and-md5-hash-functions-in-c-78c17e657794
* https://github.com/ilvn/SHA256
