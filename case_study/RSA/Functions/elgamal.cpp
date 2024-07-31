/* elgamal.c  -  elgamal Public Key encryption
 * Copyright (C) 1998, 2000, 2001, 2003,
 *               2004 Free Software Foundation, Inc.
 *
 * For a description of the algorithm, see:
 *   Bruce Schneier: Applied Cryptography. John Wiley & Sons, 1996.
 *   ISBN 0-471-11709-9. Pages 476 ff.
 *
 * This file is part of GnuPG.
 *
 * GnuPG is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * GnuPG is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mpiheader.h"
#include <sanitizer/mince_interface.h>

#define G10ERR_BAD_MPI -1
#define G10ERR_BAD_SECKEY -2
#define G10ERR_PUBKEY_ALGO -3
#define PUBKEY_USAGE_ENC 1
#define PUBKEY_ALGO_ELGAMAL_E 1
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

void populate_aes()
{
    for (int i=0;i<64*16;i=i+64) {
        __mince_populate((unsigned long)&Te0[i/4],64,i/64);
    }
}

int is_ELGAMAL(int i)
{
	return 1;
}

typedef struct {
    MPI p;	    /* prime */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
} ELG_public_key;

typedef struct {
    MPI p;	    /* prime */
    MPI g;	    /* group generator */
    MPI y;	    /* g^x mod p */
    MPI x;	    /* secret exponent */
} ELG_secret_key;


static void test_keys( ELG_secret_key *sk, unsigned nbits );
static MPI gen_k( MPI p, int small_k );
static void generate( ELG_secret_key *sk, unsigned nbits, MPI **factors );
static int  check_secret_key( ELG_secret_key *sk );
static void do_encrypt(MPI a, MPI b, MPI input, ELG_public_key *pkey );
static void decrypt(MPI output, MPI a, MPI b, ELG_secret_key *skey );


/****************
 * Michael Wiener's table about subgroup sizes to match field sizes
 * (floating around somewhere - Fixme: need a reference)
 */
static unsigned int
wiener_map( unsigned int n )
{
    static struct { unsigned int p_n, q_n; } t[] =
    {	/*   p	  q	 attack cost */
	{  512, 119 },	/* 9 x 10^17 */
	{  768, 145 },	/* 6 x 10^21 */
	{ 1024, 165 },	/* 7 x 10^24 */
	{ 1280, 183 },	/* 3 x 10^27 */
	{ 1536, 198 },	/* 7 x 10^29 */
	{ 1792, 212 },	/* 9 x 10^31 */
	{ 2048, 225 },	/* 8 x 10^33 */
	{ 2304, 237 },	/* 5 x 10^35 */
	{ 2560, 249 },	/* 3 x 10^37 */
	{ 2816, 259 },	/* 1 x 10^39 */
	{ 3072, 269 },	/* 3 x 10^40 */
	{ 3328, 279 },	/* 8 x 10^41 */
	{ 3584, 288 },	/* 2 x 10^43 */
	{ 3840, 296 },	/* 4 x 10^44 */
	{ 4096, 305 },	/* 7 x 10^45 */
	{ 4352, 313 },	/* 1 x 10^47 */
	{ 4608, 320 },	/* 2 x 10^48 */
	{ 4864, 328 },	/* 2 x 10^49 */
	{ 5120, 335 },	/* 3 x 10^50 */
	{ 0, 0 }
    };
    int i;

    for(i=0; t[i].p_n; i++ )  {
	if( n <= t[i].p_n )
	    return t[i].q_n;
    }
    /* not in table - use some arbitrary high number ;-) */
    return  n / 8 + 200;
}

static void
test_keys( ELG_secret_key *sk, unsigned int nbits )
{
    ELG_public_key pk;
    MPI test = mpi_alloc( 0 );
    MPI out1_a = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    MPI out1_b = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    MPI out2   = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );

    pk.p = sk->p;
    pk.g = sk->g;
    pk.y = sk->y;

    /*mpi_set_bytes( test, nbits, get_random_byte, 0 );*/
    {	
		unsigned char *p = get_random_bits( nbits, 0, 0 );
		mpi_set_buffer( test, p, (nbits+7)/8, 0 );
		free(p);
    }

    do_encrypt( out1_a, out1_b, test, &pk );
    decrypt( out2, out1_a, out1_b, sk );
    
    mpi_free( test );
    mpi_free( out1_a );
    mpi_free( out1_b );
    mpi_free( out2 );
}


/****************
 * Generate a random secret exponent k from prime p, so that k is
 * relatively prime to p-1.  With SMALL_K set, k will be selected for
 * better encryption performance - this must never bee used signing!
 */
static MPI
gen_k( MPI p, int small_k )
{
    MPI k = mpi_alloc( 0 );
    MPI temp = mpi_alloc( mpi_get_nlimbs(p) );
    MPI p_1 = mpi_copy(p);
    unsigned int orig_nbits = mpi_get_nbits(p);
    unsigned int nbits;
    unsigned int nbytes;
    unsigned char *rndbuf = NULL;

    if (small_k)
      {
        /* Using a k much lesser than p is sufficient for encryption and
         * it greatly improves the encryption performance.  We use
         * Wiener's table and add a large safety margin.
         */
        nbits = wiener_map( orig_nbits ) * 3 / 2;
        
      }
    else
      nbits = orig_nbits;

    nbytes = (nbits+7)/8;
   
    mpi_sub_ui( p_1, p, 1);
    for(;;) {
	if( !rndbuf || nbits < 32 ) {
	    free(rndbuf);
	    rndbuf = get_random_bits( nbits, 1, 1 );
	}
	else { /* Change only some of the higher bits. */
	    /* We could impprove this by directly requesting more memory
	     * at the first call to get_random_bits() and use this the here
	     * maybe it is easier to do this directly in random.c
	     * Anyway, it is highly inlikely that we will ever reach this code
	     */
	    unsigned char *pp = get_random_bits( 32, 1, 1 );
	    memcpy( rndbuf,pp, 4 );
	    free(pp);
	}
	mpi_set_buffer( k, rndbuf, nbytes, 0 );

	for(;;) {
	    if( !(mpi_cmp( k, p_1 ) < 0) ) {  /* check: k < (p-1) */
		break; /* no  */
	    }
	    if( !(mpi_cmp_ui( k, 0 ) > 0) ) { /* check: k > 0 */
		break; /* no */
	    }
	    if( mpi_gcd( temp, k, p_1 ) )
		goto found;  /* okay, k is relatively prime to (p-1) */
	    mpi_add_ui( k, k, 1 );
	}
    }
  found:
    free(rndbuf);
    
    mpi_free(p_1);
    mpi_free(temp);

    return k;
}

/****************
 * Generate a key pair with a key of size NBITS
 * Returns: 2 structures filles with all needed values
 *	    and an array with n-1 factors of (p-1)
 */
static void
generate(  ELG_secret_key *sk, unsigned int nbits, MPI **ret_factors )
{
    MPI p;    /* the prime */
    MPI p_min1;
    MPI g;
    MPI x;    /* the secret exponent */
    MPI y;
    MPI temp;
    unsigned int qbits;
    unsigned int xbits;
    byte *rndbuf;

    p_min1 = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    temp   = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    qbits  = wiener_map ( nbits );
    if( qbits & 1 ) /* better have a even one */
		qbits++;
    g = mpi_alloc(1);
    
    p = generate_elg_prime( 0, nbits, qbits, g, ret_factors );
   
    mpi_sub_ui(p_min1, p, 1);

    /* select a random number which has these properties:
     *	 0 < x < p-1
     * This must be a very good random number because this is the
     * secret part.  The prime is public and may be shared anyway,
     * so a random generator level of 1 is used for the prime.
     *
     * I don't see a reason to have a x of about the same size as the
     * p.  It should be sufficient to have one about the size of q or
     * the later used k plus a large safety margin. Decryption will be
     * much faster with such an x.  Note that this is not optimal for
     * signing keys becuase it makes an attack using accidential small
     * K values even easier.  Well, one should not use ElGamal signing
     * anyway.
     */
    xbits = qbits * 3 / 2;
   
    x = mpi_alloc_secure ( mpi_nlimb_hint_from_nbits (xbits) );
    
    rndbuf = NULL;
    do {
		
		if( rndbuf ) { /* change only some of the higher bits */
			
			if( xbits < 16 ) {/* should never happen ... */
				free(rndbuf);
				rndbuf = get_random_bits( xbits, 2, 1 );
			}
			else {
				unsigned char *r = get_random_bits( 16, 2, 1 );
				memcpy(rndbuf, r, 16/8 );
				free(r);
			}
		}
		else
		{
			rndbuf = get_random_bits( xbits, 2, 1 );
		}
		
		mpi_set_buffer( x, rndbuf, (xbits+7)/8, 0 );
		mpi_clear_highbit( x, xbits+1 );
		
    } while( !( mpi_cmp_ui( x, 0 )>0 && mpi_cmp( x, p_min1 )<0 ) );
    free(rndbuf);
	
    y = mpi_alloc ( mpi_nlimb_hint_from_nbits (nbits) );
    mpi_powm( y, g, x, p );

    /* copy the stuff to the key structures */
    sk->p = p;
    sk->g = g;
    sk->y = y;
    sk->x = x;

    /* now we can test our keys (this should never fail!) */
    test_keys( sk, nbits - 64 );

    mpi_free( p_min1 );
    mpi_free( temp   );
}


/****************
 * Test whether the secret key is valid.
 * Returns: if this is a valid key.
 */
static int
check_secret_key( ELG_secret_key *sk )
{
    int rc;
    MPI y = mpi_alloc( mpi_get_nlimbs(sk->y) );

    mpi_powm( y, sk->g, sk->x, sk->p );
    rc = !mpi_cmp( y, sk->y );
    mpi_free( y );
    return rc;
}


static void
do_encrypt(MPI a, MPI b, MPI input, ELG_public_key *pkey )
{
    MPI k;

    /* Note: maybe we should change the interface, so that it
     * is possible to check that input is < p and return an
     * error code.
     */

    k = gen_k( pkey->p, 1 );
    mpi_powm( a, pkey->g, k, pkey->p );
    /* b = (y^k * input) mod p
     *	 = ((y^k mod p) * (input mod p)) mod p
     * and because input is < p
     *	 = ((y^k mod p) * input) mod p
     */
    mpi_powm( b, pkey->y, k, pkey->p );
    mpi_mulm( b, b, input, pkey->p );

    mpi_free(k);
}


static void
decrypt(MPI output, MPI a, MPI b, ELG_secret_key *skey )
{
	int i;
	MPI x = skey->x;
	
    MPI t1 = mpi_alloc( mpi_get_nlimbs( skey->p ) );

    /* output = b/(a^x) mod p */
    mpi_powm( t1, a, skey->x, skey->p );
    mpi_invm( t1, t1, skey->p );
    mpi_mulm( output, b, t1, skey->p );

    mpi_free(t1);
}


/*********************************************
 **************  interface  ******************
 *********************************************/

int
elg_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
		return G10ERR_PUBKEY_ALGO;

    generate( &sk, nbits, retfactors );

    skey[0] = sk.p;
    skey[1] = sk.g;
    skey[2] = sk.y;
    skey[3] = sk.x;
    return 0;
}


int
elg_check_secret_key( int algo, MPI *skey )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
		return G10ERR_PUBKEY_ALGO;
    if( !skey[0] || !skey[1] || !skey[2] || !skey[3] )
		return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.g = skey[1];
    sk.y = skey[2];
    sk.x = skey[3];
    if( !check_secret_key( &sk ) )
		return G10ERR_BAD_SECKEY;

    return 0;
}


int
elg_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey )
{
    ELG_public_key pk;

    if( !is_ELGAMAL(algo) )
		return G10ERR_PUBKEY_ALGO;
    if( !data || !pkey[0] || !pkey[1] || !pkey[2] )
		return G10ERR_BAD_MPI;

    pk.p = pkey[0];
    pk.g = pkey[1];
    pk.y = pkey[2];
    resarr[0] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
    resarr[1] = mpi_alloc( mpi_get_nlimbs( pk.p ) );
    do_encrypt( resarr[0], resarr[1], data, &pk );
    return 0;
}

int
elg_decrypt( int algo, MPI *result, MPI *data, MPI *skey )
{
    ELG_secret_key sk;

    if( !is_ELGAMAL(algo) )
	return G10ERR_PUBKEY_ALGO;
    if( !data[0] || !data[1]
	|| !skey[0] || !skey[1] || !skey[2] || !skey[3] )
	return G10ERR_BAD_MPI;

    sk.p = skey[0];
    sk.g = skey[1];
    sk.y = skey[2];
    sk.x = skey[3];
    *result = mpi_alloc( mpi_get_nlimbs( sk.p ) );
    decrypt( *result, data[0], data[1], &sk );
    return 0;
}


unsigned int
elg_get_nbits( int algo, MPI *pkey )
{
    if( !is_ELGAMAL(algo) )
	return 0;
    return mpi_get_nbits( pkey[0] );
}


/****************
 * Return some information about the algorithm.  We need algo here to
 * distinguish different flavors of the algorithm.
 * Returns: A pointer to string describing the algorithm or NULL if
 *	    the ALGO is invalid.
 * Usage: Bit 0 set : allows signing
 *	      1 set : allows encryption
 */
const char *
elg_get_info( int algo, int *npkey, int *nskey, int *nenc, int *nsig,
							 int *use )
{
    *npkey = 3;
    *nskey = 4;
    *nenc = 2;
    *nsig = 2;

    switch( algo ) {
      case PUBKEY_ALGO_ELGAMAL_E:
	*use = PUBKEY_USAGE_ENC;
	return "ELG-E";
      default: *use = 0; return NULL;
    }
}
