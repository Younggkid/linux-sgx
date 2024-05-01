/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <vector>
#include <set>
#include <algorithm>
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include <sanitizer/mince_interface.h>
#include "sgx_trts.h"
#include <math.h>
//using std::random_shuffle;
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
#define PAGE_SIZE 4096
int secret[256] __attribute__((aligned (4096)));
uint64_t counter = 0;
uint64_t* c = &counter;
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

void populate()
{
    for (int i=0;i<16*64;i=i+64) {
        __mince_populate((unsigned long)&secret[i/4],64,i/64);
    }
}
/* for verifiable contract with OS*/
typedef struct primelist *primelist_t;
struct primelist 
{
	primelist_t probe;
	primelist_t prime;
	int data;
};
typedef uint64_t pointer;
void insert(primelist_t &list, uint64_t addr)
{
	if(list == NULL)
	{
		//printf("inserting first element..\n");
		primelist_t cur = (primelist_t)addr;
		cur->probe = NULL;
		cur->prime = NULL;
		cur->data = 0;
		
		list = cur;
		
		//printf("inserted first element..\n");
		return;
	}
	
	primelist_t last = list;
	primelist_t cur = (primelist_t)addr;
	
	while(last->probe != NULL)
		 last = last->probe;
    cur->prime = last;
    last->probe = cur;
    cur->probe = NULL;
    cur->data = 0;
    
    list = cur;
    //printf("inserted: %p, previous addr: %p\n", addr, cur->prime);
}

unsigned long __attribute__ ((noinline)) warmup(primelist_t le) {
  volatile int l = 0;
  
  asm __volatile__ (
    "  xorl %%edi, %%edi	\n"
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    "  mov 8(%1),%1		\n"
    //probe again
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  mov (%1),%1		\n"
    "  lfence         \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
    "  movl %%edi, %0		\n"
      :"=a" (l)
      :"b" (le)
      :"%edx","%esi", "%rdi", "%ecx");
  return l;
}

primelist_t initList() 
{
	return NULL;
}

unsigned long __attribute__ ((noinline)) candi_access(void* p) {
  volatile int l = 0;
  volatile unsigned long start = counter;
    asm __volatile__ (
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  movq (%1), %%rdx		\n"
    "  lfence         \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
      :"=a" (l)
      :"b" (p));
  volatile unsigned long end = counter;
  return (end-start);
}

unsigned long __attribute__ ((noinline)) empty_access() {
  volatile int l = 0;
  volatile unsigned long start = counter;
    asm __volatile__ (
    //"  xorq %%rdx, %%rdx	\n"
    "  mfence                   \n"
    "  lfence                   \n"
    "  lfence         \n"
    //"  incl %%edi		\n"
    //"  cmpl $12, %%edi		\n" //jump if edi < first num
    //"  jle LL			\n"
      :"=a" (l));
  volatile unsigned long end = counter;
  return (end - start);
}

/*traversing the prime list until the NULL pointer*/
void __attribute__ ((noinline)) prime(primelist_t probeLink) {
  asm __volatile__ (
    "L4:			\n"
//    "  incl 16(%0)               \n"
    "  mov 8(%0), %0		\n"
    "  test %0, %0		\n"
    "  jne L4			\n"
  : : "r" (probeLink) : );
}


/*traversing the prime list until the NULL pointer*/
void __attribute__ ((noinline)) probe(primelist_t probeLink) {
  asm __volatile__ (
    "L5:			\n"
 //   "  incl 16(%0)               \n"
    "  mov (%0), %0		\n"
    "  test %0, %0		\n"
    "  jne L5			\n"
  : : "r" (probeLink) : );
}

void shuffle(std::vector<uint64_t> arr, int n)
{
    uint32_t val;
   
    sgx_read_rand((unsigned char*)&val,4);
    val = val%n;
    if (n > 1) 
    {
        int i;
        for (i = 0; i < n - 1; i++) 
        {
          int j = (i + val)%n;
          uint64_t t = arr[j];
          arr[j] = arr[i];
          arr[i] = t;
        }
    }
}

void run_vec()
{
  
  std::vector<uint64_t> myvectorA;
  primelist_t primeprobelistA = initList();
  int countA = 0;
  pointer candidate = 0;
  pointer start_addr = (pointer)get_mince_start_addr();
  candidate = start_addr;
  for (int i=1;i<16;++i)
  {
    pointer addr = start_addr + i*PAGE_SIZE;
    //printf("page addr is %p\n",addr);
    countA++;
    myvectorA.push_back(addr);
  }
  shuffle(myvectorA,15);
  //printf("random number is %d\n",val%16);
  countA = 0;
	for (std::vector<uint64_t>::iterator it=myvectorA.begin(); it!=myvectorA.end() && countA < 12; ++it, ++countA)
	{
		insert(primeprobelistA, *it);
	}

  primelist_t primeListsA =  primeprobelistA;
	primelist_t probeListsA =  primeprobelistA;

  while(probeListsA->prime != NULL)
		probeListsA = probeListsA->prime;
  

  unsigned long baseline = empty_access();
  unsigned long time1 = candi_access((void*)candidate);
  unsigned long time2 = candi_access((void*)candidate);
  for (int i=0;i<100;++i)
  {
  prime(primeListsA);
  prime(primeListsA);
  probe(probeListsA);
  prime(primeListsA);
  probe(probeListsA);
  }
  unsigned long time3 = candi_access((void*)candidate);
  //bool islarger = (time3 > time2);
  printf("%ld,%ld\n",time2 , time3);


}
int printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return 0;
}

