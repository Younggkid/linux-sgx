#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "string.h"
#include <sanitizer/mince_interface.h>
#include <iosfwd>

int secret[32] __attribute__((aligned (4096)));
uint64_t counter = 0;
uint64_t* c = &counter;


void populate()
{
    for (int i=0;i<128;i=i+64) {
        __mince_populate((unsigned long)&secret[i/4],64,i/64);
    }
}

void secure_timer()
{
              asm volatile(
                 "mov %0, %%rcx\n\t"
                 "1: inc %%rax\n\t"
                 "mov %%rax, (%%rcx)\n\t"
                 "jmp 1b\n\t"
                 : "=rm"(c)
                 : "r"(c)
                 : "%rax", "%rbx", "%rdx");

}

uint64_t time_cost()
{
  int a = 1;
  uint64_t start = counter;
  for (int i=0;i<1000;++i){
    a++;
  }
  uint64_t end = counter;

  return (end - start);

}


extern "C"
void fibnacci(int n) __attribute__((mince)) // 4
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
  printf("cost %d\n",time_cost());
}



