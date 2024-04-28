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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <sched.h>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <stdlib.h>
#include <stdint.h>
pthread_t thread1;
unsigned long rdtsc_begin() {
    unsigned long a, d;
    asm volatile("mfence\n\t"
                 "CPUID\n\t"
                 "RDTSCP\n\t"
                 "mov %%rdx, %0\n\t"
                 "mov %%rax, %1\n\t"
                 "mfence\n\t"
                 : "=r"(d), "=r"(a)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}

unsigned long rdtsc_end() {
    unsigned long a, d;
    asm volatile("mfence\n\t"
                 "RDTSCP\n\t"
                 "mov %%rdx, %0\n\t"
                 "mov %%rax, %1\n\t"
                 "CPUID\n\t"
                 "mfence\n\t"
                 : "=r"(d), "=r"(a)
                 :
                 : "%rax", "%rbx", "%rcx", "%rdx");
    a = (d << 32) | a;
    return a;
}

void *secure_timer_thread_function(void* param)
{
    secure_timer(global_eid);
    return (void *)0;
}

void sched_threads(int i)
{
    printf("sched threads here!\n");
    
    int core_main = 0, core_timer = 2;
    cpu_set_t cpus;
    pthread_attr_t attr;
    pthread_attr_init(&attr);

    CPU_ZERO(&cpus);
    CPU_SET(core_main, &cpus);
    sched_setaffinity(0,sizeof(cpu_set_t),&cpus);

    CPU_ZERO(&cpus);
    CPU_SET(core_timer, &cpus);
    pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
    pthread_create(&thread1, &attr, secure_timer_thread_function, NULL);

    pthread_setname_np(thread1, "sectimer");
}
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        printf("create unsuccessfully, error = %x\n", ret);
        return -1;
    }
    printf("create successfully\n");


    // add ecall here!
    //int ret = sgx_contact_driver(global_eid);
    sched_threads(0);
    populate(global_eid);
    int start = rdtsc_begin();
    fibnacci(global_eid,12);
    int end = rdtsc_end();
    printf("The cycles is %d\n",end -start);
    //int cpuid[4] = {0x0, 0x0, 0x0, 0x0};
    //ret = ecall_sgx_cpuid(global_eid, cpuid, 0x0);
    if (ret != SGX_SUCCESS)
        abort();
    sleep(2);
    if(0!=pthread_cancel(thread1))
        printf("cancel failed!\n");
    int res = pthread_join(thread1, NULL);
    sgx_destroy_enclave(global_eid);

    printf("Info: SampleEnclave successfully returned.\n");
    return 0;
}
