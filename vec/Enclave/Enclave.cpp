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
unsigned int  Te0[256] __attribute__((aligned (64))) = {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU,
} ;
void secure_timer()
{
    asm volatile(
        "mov %0, %%rcx\n\t"
        "1: inc %%rax\n\t"
        "mov %%rax, (%%rcx)\n\t"
        //"mfence\n\t"
        //"jmp 1b\n\t"
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
  
   for (int i=0;i<8*1024;++i){
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
	for (std::vector<uint64_t>::iterator it=myvectorA.begin(); it!=myvectorA.end() && countA < 8; ++it, ++countA)
	{
		insert(primeprobelistA, *it);
	}

  primelist_t primeListsA =  primeprobelistA;
	primelist_t probeListsA =  primeprobelistA;

  while(probeListsA->prime != NULL)
		probeListsA = probeListsA->prime;
  

  unsigned long baseline = empty_access();
  baseline = empty_access();
  unsigned long time1 = candi_access((void*)candidate);
  unsigned long time2 = candi_access((void*)candidate);
  for (int i=0;i<5;++i)
  {
  prime(primeListsA);
  prime(primeListsA);
  probe(probeListsA);
  }
  unsigned long time3 = candi_access((void*)candidate);
  //bool islarger = (time3 > time2);
  printf("%ld, %ld\n",time2 , time3);
   }


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

