/* This file follows obfuscuro to create a communication channel betweeen an
 * SGX Enclave and the SGX device driver. 
 */
#include "arch.h"
#include "tcs.h"
#include "xsave.h"
#include "rts.h"

#include "enclave_creator_hw.h"
#include "se_trace.h"
#include "se_page_attr.h"
#include "isgx_user.h"
#include "sig_handler.h"
#include "se_error_internal.h"
#include "se_memcpy.h"
#include "se_atomic.h"
#include "se_detect.h"
#include "sgx_urts.h"
#include "enclave.h"

#include "cpuid.h"
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "isgx_user.h"
#include "sgx_error.h"

#define DEBUG 1

struct enclave enclaveTab[MAXENCLAVES];
unsigned long enclavePageTable[MAXPAGES];

static sgx_enclave_id_t tmp_enclave_id; 

int pfault_counter = 0;

void reset_pfault_counter()
{
	pfault_counter = 0;
}

int get_pfault_counter() {
	return pfault_counter;
}

void debug_pageTable (unsigned long enclave_id) {
    DOUT("debugging page table!\n");
    struct enclave* enc = &enclaveTab[(enclave_id%MAXENCLAVES)];
    if (enc == NULL) {
        DOUT("[ERR] Can't get enclave entry\n");
        return;
    }
    DOUT("filled pages: %d\n", enc->filled);
    for (int i=0;i<enc->filled;i++) {
        DOUT("page addr: %lx\n", enc->pageTable[i]);
    }

}
/*
void sgx_contact_enclave(unsigned long addr) 
{
	//DOUT("will contact enclave %ld for addr %ld\n", 
	//	tmp_enclave_id, addr);
	CEnclave* enclave = CEnclavePool::instance()->get_enclave(tmp_enclave_id);
        if (enclave == NULL) {
		DOUT("[SDK][ERR] Couldn't get the enclave\n");
    		return;
        }

	unsigned long *s_addr = (unsigned long*) malloc(sizeof(unsigned long));
	memcpy(s_addr, &addr, sizeof(unsigned long));

	// now contact the enclave
	// change this 1 to the # of the ecall which is responsible for page
	// swapping etc.
	// DEFAULT: 0 --> initialize, 1 --> swapin, 2 --> swapout
	// TODO: implement for swapout

	// get free tcs for this swap-in/out job
	CTrustThread* newThread = enclave->get_free_tcs();
	if (newThread == NULL) {
		DOUT("Couldn't get the thread\n");
		return;
	}
	
	int ret = do_ecall(1, tmp_ocall_table, (void*) s_addr, newThread);
	if (ret != 0) {
		DOUT("Error while trying ECALL\n");
	}

	enclave->put_free_tcs(newThread);
}
*/


struct enclave* sgx_get_pagetable(sgx_enclave_id_t enclave_id) {
    CEnclave* enclave = CEnclavePool::instance()->get_enclave(enclave_id);
    if (enclave == NULL) {
        DOUT("[SDK][ERR] Couldn't get the enclave\n");
        return NULL;
    }

    unsigned long enclave_addr = (unsigned long) enclave->get_start_address();

    struct enclave *enc = &enclaveTab[(enclave_addr%MAXENCLAVES)];

    return enc;

}
// untested
// need to redefine the SGX_IOC_ENCLAVE_VATRANS
/*
uint64_t sgx_vaddr_translate(sgx_enclave_id_t enclave_id, unsigned long vaddr)
{
    int ret = 0;
    
    struct sgx_enclave_vatrans enc_vatrans = { 0, 0, 0 };

    int fd = open("/dev/isgx", O_RDWR);
    if (fd < 0) return -1;

    CEnclave* enclave = CEnclavePool::instance()->get_enclave(enclave_id);
    if (enclave == NULL) {
        DOUT("[SDK][ERR] Couldn't get the enclave\n");
        return -1;
    }

    enc_vatrans.enclave_id = (__u64) enclave->get_start_address();
    enc_vatrans.vaddr = (__u64) vaddr;

    DOUT("Contacting the kernel to translate vaddr: %lx\n", vaddr);
    ret = ioctl(fd, (SGX_IOC_ENCLAVE_VATRANS), &enc_vatrans);
    if (ret) {
        DOUT("[ERR] error translating the vaddr\n");
        return -1;
    }

    DOUT("Translation successful, vaddr %llx, paddr %llx\n", enc_vatrans.vaddr, enc_vatrans.paddr);

    return enc_vatrans.paddr;


}
*/


int sgx_contact_driver(sgx_enclave_id_t enclave_id)
{
        int ret = 0;

        // create a structure for storing page information
        struct sgx_enclave_pginfo enc_pginfo = { 0, 0 };        

        // poll the device driver
        int fd = open("/dev/isgx", O_RDWR);
        if (fd < 0) 
                return -1;
                
        // use the enclave id to get start address of enclave
        CEnclave* enclave = CEnclavePool::instance()->get_enclave(enclave_id);
        if (enclave == NULL) {
		DOUT("[SDK][ERR] Couldn't get the enclave\n");
    		return -1;
        }       
	enc_pginfo.enclave_id = (__u64) enclave->get_start_address();
	enc_pginfo.pid = (__u64) getpid();

	// save the id for future
	tmp_enclave_id = enclave_id;

	DOUT("Contacting Kernel for Page Information for addr %llx and pid %lld \n",
		 enc_pginfo.enclave_id, enc_pginfo.pid);

        // test the connection
        ret = ioctl(fd, SGX_IOC_ENCLAVE_PSETUP, &enc_pginfo);
	if (ret) { 
		DOUT("[ERR] error setting up page info\n");
		return -1;
 	}
        DOUT("connection test SUCCESS\n"); 

        if (DEBUG == 1) {
		// get information about the pages assigned to this enclave
		unsigned long enclave_addr = enc_pginfo.enclave_id;
		debug_pageTable(enclave_addr);
	}

        return ret;
}