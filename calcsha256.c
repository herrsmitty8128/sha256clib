
//           Copyright Christopher Smith 2022.
// Distributed under the Boost Software License, Version 1.0.
//      (See accompanying file LICENSE.txt or copy at
//          https://www.boost.org/LICENSE_1_0.txt)

#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#define BUFF_SIZE 1024

int main(int nargs, char** args){

    char file_name[BUFF_SIZE] = {'\0'};
    uint32_t digest[8];

    if(nargs <= 1){ /* no args were passed */
        printf("Please enter a file name and path: ");
        fflush(stdout);
        if(fgets(file_name, BUFF_SIZE-1, stdin)==NULL){
            printf("Error reading from stdin\n");
            return EXIT_FAILURE;
        }
        for(int i = 0; i < BUFF_SIZE-1; i++){
            if(file_name[i] == 0x0a || file_name[i] == 0x0d || file_name[i] == '\0'){
                file_name[i] = '\0';
                break;
            }
        }
    }
    else{     /* at least one arg was passed */
        char* arg = args[nargs-1];
        for(int i = 0; i < BUFF_SIZE-1; i++){
            file_name[i] = arg[i];
            if(arg[i] == '\0') break;
        }
    }

    if(sha256_fileToDigest(file_name, digest)){
        sha256_printDigestAsHex(digest);
        printf("\n");
        return EXIT_SUCCESS;
    }
    
    printf("Error calculating sha256 digest\n");
    
    return EXIT_FAILURE;
}