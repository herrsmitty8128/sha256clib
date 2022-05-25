
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include "sha256.h"
#include <string.h>
#include <stdio.h>

int main(){

    FILE* f = fopen("./testDataFile.csv","rb");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t* message = (uint8_t*)malloc(size + 1);
    if(!message){
        fclose(f);
        return 0;
    }
    fread(message, 1, size, f);
    fclose(f);

    uint32_t digest[8];
    uint32_t digest2[8];
    char str[65];
    
    if(calcSHA256((uint8_t*)message, size, digest)){
        printf("sha256sum digest:  %s\n","76e948bcc2d893fdf0bbb30a3d79673c9611611feef6b23654c4e03c4e6c258c");
        printf("Calculated digest: ");
        printDigestAsHex(digest);
        printf("\n");
        digestToHex(digest, str);
        printf("Digest as hex:     %s\n",str);
        hexToDigest(str, digest2);
        if(digestsAreEqual(digest, digest2)){
            printf("hex2Digest test:   SUCCESSFUL\n");
        }
        else{
            printf("hex2Digest test:   FAILED\n");
        }
    }
    free(message);
}