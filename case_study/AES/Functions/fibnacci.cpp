#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "string.h"
#include <sanitizer/mince_interface.h>
#include <iosfwd>
//#include <vector>
//#include <string>
//#include <sgx_trts.h>

int secret[256] __attribute__((aligned (4096)));


extern "C"
void fibnacci(int n)
{   

    int cur = 0; //8
  int next = 1; //0c
  int count = 0; //10
  for (int i = 0;i<32;++i) {
    secret[i] = 0;
  }
  for (int i = 2; i <= n; i++) { //14
    secret[22] = cur + next;
    cur = next;
    next = secret[22];
  }

  printf("a is %d\n",secret[22]);
  // printf("cost %d\n",time_cost());
}



