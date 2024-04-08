#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "string.h"
#include <sanitizer/mince_interface.h>

int secret[32];

void populate()
{
    for (int i=0;i<64;i=i+64) {
        __mince_populate((unsigned long)&secret[i/4],64,i/64);
    }
}

extern "C"
void fibnacci(int n) //__attribute__((mince)) // 4
{   
    int cur = 0; //8
  int next = 1; //0c
  int count = 0; //10
  for (int i = 0;i<32;++i) {
    secret[i] = 0;
  }
  for (int i = 2; i <= n; i++) { //14
    secret[0] = cur + next;
    cur = next;
    next = secret[0];
  }
  printf("a is %d\n",secret[0]);
  


}


