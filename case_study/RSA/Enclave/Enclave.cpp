/*
 * Copyright (C) 2011-2016 Intel Corporation. All rights reserved.
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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include "sgx_cpuid.h"
#include "Enclave.h"
#include "sgx_trts.h"
#include "Enclave_t.h"  /* print_string */
#include <sanitizer/mince_interface.h>
#include "string.h"
#include "../Functions/mpiheader.h"



/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void populate()
{
  //populate_aes();
}
int nbits = 1024;
MPI skey[4]; MPI *retfactors;

MPI test = mpi_alloc( 0 );
MPI out1[2];

MPI pk[3];
extern bool flagprint;

int FM()
{
	elg_generate(0, nbits, skey, &retfactors);

	for(int i = 0; i < skey[3]->nlimbs; i++)   // x
	{
		//TRACE(14, skey[3]->d[i]);
	
	//MYDEBUG(skey[3]->nlimbs);                // 4
	//MYDEBUG(elg_check_secret_key(1, skey));  // 0
	//printf("nlimbs is %ld",skey[3]->nlimbs);
	printf("the addr is %lx\n",(uint64_t)&mpih_sqr_n_basecase);
	//TRACE(14, (uint64_t)&elg_decrypt);
	
    pk[0] = skey[0];
    pk[1] = skey[1];
    pk[2] = skey[2];
	
    	unsigned char *p = get_random_bits( nbits, 0, 0 );
		mpi_set_buffer( test, p, (nbits+7)/8, 0 );
		free(p);
    }	
	
    elg_encrypt(1, out1, test, pk);
    return 1;
}

/*int testvar[1000] = {10};

void maccess2(void *p)
{
//	asm volatile ("clflush 0(%0)\n" :: "r" (p) : "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
	asm volatile ("movq (%0), %%rax" :: "r" (p) : "memory", "rax");
	asm volatile ("mfence");
}*/

void decrypt()
{
	//while(1)
	//{  
		MPI out2;
		int testvar2 = 0;
//		flagprint = true;
	//for(int i = 0; i < 1; i++)
	//{
	//	TRACE(14, (uint64_t)&testvar[500]);
	//	maccess2(&testvar[500]);
	for(int i = 0; i < 20; i++)
		elg_decrypt(1, &out2, out1, skey);
	//}
//	MYDEBUG(1000);
//		for(int i = 0; i < out2->nlimbs; i++)   // secret exponent
	//	{
//			TRACE(14, out2->d[i]);
//		}
//		mpi_free(out2);
//		enclsleep(1000000);
//		MYDEBUG(out2->nlimbs);
	//}
    
	
}

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
