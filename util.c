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