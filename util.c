#include <stdio.h>

void printCharInHexadecimal(const unsigned char* str, int len) {
  for (int i = 0; i < len; ++ i) {

    unsigned char val = str[i];

    char tbl[] = "0123456789ABCDEF";
    //printf("0x");
    printf("%c", tbl[val / 16]);
    printf("%c", tbl[val % 16]);
    //printf(" ");
  }
  printf("\n");
}

void printBytes(unsigned char *address, int size) {
    int count;
    for (count = 0; count < size; count++){
        printf("%.2x", address[count]);
    }
    printf("\n");
}

