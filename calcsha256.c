
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define BUFF_SIZE 1024

int main(int nargs, char** args){

    char file_name[BUFF_SIZE];
    uint32_t digest[8];

    if(nargs <= 1){ /* no args were passed */
        printf("Please enter a file name and path: ");
        fflush(stdout);
        read(STDIN_FILENO, file_name, BUFF_SIZE);
        int len = strnlen(file_name, BUFF_SIZE);
        for(int i = 0; i < len; i++){
            if(file_name[i] == 0x0a || file_name[i] == 0x0d) file_name[i] = '\0';
        }
    }
    else{     /* at lease one arg was passed */
        strncpy(file_name, args[nargs - 1], BUFF_SIZE);
    }

    if(sha256_fileToDigest(file_name, digest)){
        sha256_printDigestAsHex(digest);
        printf("\n");
        return EXIT_SUCCESS;
    }
    
    printf("Error calculating sha256 digest.\n");
    
    return EXIT_FAILURE;
}