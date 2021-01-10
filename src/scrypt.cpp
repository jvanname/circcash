/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2012-2013 pooler
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "scrypt.h"
#include "util.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <assert.h>
#include <math.h>



#if defined(USE_SSE2) && !defined(USE_SSE2_ALWAYS)
#ifdef _MSC_VER
// MSVC 64bit is unable to use inline asm
#include <intrin.h>
#else
// GCC Linux or i686-w64-mingw32
#include <cpuid.h>
#endif
#endif

static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}

typedef struct HMAC_SHA256Context {
	SHA256_CTX ictx;
	SHA256_CTX octx;
} HMAC_SHA256_CTX;

/* Initialize an HMAC-SHA256 operation with the given key. */
static void
HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *_K, size_t Klen)
{
	unsigned char pad[64];
	unsigned char khash[32];
	const unsigned char *K = (const unsigned char *)_K;
	size_t i;

	/* If Klen > 64, the key is really SHA256(K). */
	if (Klen > 64) {
		SHA256_Init(&ctx->ictx);
		SHA256_Update(&ctx->ictx, K, Klen);
		SHA256_Final(khash, &ctx->ictx);
		K = khash;
		Klen = 32;
	}

	/* Inner SHA256 operation is SHA256(K xor [block of 0x36] || data). */
	SHA256_Init(&ctx->ictx);
	memset(pad, 0x36, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->ictx, pad, 64);

	/* Outer SHA256 operation is SHA256(K xor [block of 0x5c] || hash). */
	SHA256_Init(&ctx->octx);
	memset(pad, 0x5c, 64);
	for (i = 0; i < Klen; i++)
		pad[i] ^= K[i];
	SHA256_Update(&ctx->octx, pad, 64);

	/* Clean the stack. */
	memset(khash, 0, 32);
}

/* Add bytes to the HMAC-SHA256 operation. */
static void
HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len)
{
	/* Feed data to the inner SHA256 operation. */
	SHA256_Update(&ctx->ictx, in, len);
}

/* Finish an HMAC-SHA256 operation. */
static void
HMAC_SHA256_Final(unsigned char digest[32], HMAC_SHA256_CTX *ctx)
{
	unsigned char ihash[32];

	/* Finish the inner SHA256 operation. */
	SHA256_Final(ihash, &ctx->ictx);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Update(&ctx->octx, ihash, 32);

	/* Finish the outer SHA256 operation. */
	SHA256_Final(digest, &ctx->octx);

	/* Clean the stack. */
	memset(ihash, 0, 32);
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen, const uint8_t *salt,
    size_t saltlen, uint64_t c, uint8_t *buf, size_t dkLen)
{
	HMAC_SHA256_CTX PShctx, hctx;
	size_t i;
	uint8_t ivec[4];
	uint8_t U[32];
	uint8_t T[32];
	uint64_t j;
	int k;
	size_t clen;

	/* Compute HMAC state after processing P and S. */
	HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
	HMAC_SHA256_Update(&PShctx, salt, saltlen);

	/* Iterate through the blocks. */
	for (i = 0; i * 32 < dkLen; i++) {
		/* Generate INT(i + 1). */
		be32enc(ivec, (uint32_t)(i + 1));

		/* Compute U_1 = PRF(P, S || INT(i)). */
		memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
		HMAC_SHA256_Update(&hctx, ivec, 4);
		HMAC_SHA256_Final(U, &hctx);

		/* T_i = U_1 ... */
		memcpy(T, U, 32);

		for (j = 2; j <= c; j++) {
			/* Compute U_j. */
			HMAC_SHA256_Init(&hctx, passwd, passwdlen);
			HMAC_SHA256_Update(&hctx, U, 32);
			HMAC_SHA256_Final(U, &hctx);

			/* ... xor U_j ... */
			for (k = 0; k < 32; k++)
				T[k] ^= U[k];
		}

		/* Copy as many bytes as necessary into buf. */
		clen = dkLen - i * 32;
		if (clen > 32)
			clen = 32;
		memcpy(&buf[i * 32], T, clen);
	}

	/* Clean PShctx, since we never called _Final on it. */
	memset(&PShctx, 0, sizeof(HMAC_SHA256_CTX));
}

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static inline void xor_salsa8(uint32_t B[16], const uint32_t Bx[16])
{
	uint32_t x00,x01,x02,x03,x04,x05,x06,x07,x08,x09,x10,x11,x12,x13,x14,x15;
	int i;

	x00 = (B[ 0] ^= Bx[ 0]);
	x01 = (B[ 1] ^= Bx[ 1]);
	x02 = (B[ 2] ^= Bx[ 2]);
	x03 = (B[ 3] ^= Bx[ 3]);
	x04 = (B[ 4] ^= Bx[ 4]);
	x05 = (B[ 5] ^= Bx[ 5]);
	x06 = (B[ 6] ^= Bx[ 6]);
	x07 = (B[ 7] ^= Bx[ 7]);
	x08 = (B[ 8] ^= Bx[ 8]);
	x09 = (B[ 9] ^= Bx[ 9]);
	x10 = (B[10] ^= Bx[10]);
	x11 = (B[11] ^= Bx[11]);
	x12 = (B[12] ^= Bx[12]);
	x13 = (B[13] ^= Bx[13]);
	x14 = (B[14] ^= Bx[14]);
	x15 = (B[15] ^= Bx[15]);
	for (i = 0; i < 8; i += 2) {
		/* Operate on columns. */
		x04 ^= ROTL(x00 + x12,  7);  x09 ^= ROTL(x05 + x01,  7);
		x14 ^= ROTL(x10 + x06,  7);  x03 ^= ROTL(x15 + x11,  7);

		x08 ^= ROTL(x04 + x00,  9);  x13 ^= ROTL(x09 + x05,  9);
		x02 ^= ROTL(x14 + x10,  9);  x07 ^= ROTL(x03 + x15,  9);

		x12 ^= ROTL(x08 + x04, 13);  x01 ^= ROTL(x13 + x09, 13);
		x06 ^= ROTL(x02 + x14, 13);  x11 ^= ROTL(x07 + x03, 13);

		x00 ^= ROTL(x12 + x08, 18);  x05 ^= ROTL(x01 + x13, 18);
		x10 ^= ROTL(x06 + x02, 18);  x15 ^= ROTL(x11 + x07, 18);

		/* Operate on rows. */
		x01 ^= ROTL(x00 + x03,  7);  x06 ^= ROTL(x05 + x04,  7);
		x11 ^= ROTL(x10 + x09,  7);  x12 ^= ROTL(x15 + x14,  7);

		x02 ^= ROTL(x01 + x00,  9);  x07 ^= ROTL(x06 + x05,  9);
		x08 ^= ROTL(x11 + x10,  9);  x13 ^= ROTL(x12 + x15,  9);

		x03 ^= ROTL(x02 + x01, 13);  x04 ^= ROTL(x07 + x06, 13);
		x09 ^= ROTL(x08 + x11, 13);  x14 ^= ROTL(x13 + x12, 13);

		x00 ^= ROTL(x03 + x02, 18);  x05 ^= ROTL(x04 + x07, 18);
		x10 ^= ROTL(x09 + x08, 18);  x15 ^= ROTL(x14 + x13, 18);
	}
	B[ 0] += x00;
	B[ 1] += x01;
	B[ 2] += x02;
	B[ 3] += x03;
	B[ 4] += x04;
	B[ 5] += x05;
	B[ 6] += x06;
	B[ 7] += x07;
	B[ 8] += x08;
	B[ 9] += x09;
	B[10] += x10;
	B[11] += x11;
	B[12] += x12;
	B[13] += x13;
	B[14] += x14;
	B[15] += x15;
}

void scrypt_1024_1_1_256_sp_generic(const char *input, char *output, char *scratchpad)
{
	uint8_t B[128];
	uint32_t X[32];
	uint32_t *V;
	uint32_t i, j, k;

	V = (uint32_t *)(((uintptr_t)(scratchpad) + 63) & ~ (uintptr_t)(63));

	PBKDF2_SHA256((const uint8_t *)input, 80, (const uint8_t *)input, 80, 1, B, 128);

	for (k = 0; k < 32; k++)
		X[k] = le32dec(&B[4 * k]);

	for (i = 0; i < 1024; i++) {
		memcpy(&V[i * 32], X, 128);
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}
	for (i = 0; i < 1024; i++) {
		j = 32 * (X[16] & 1023);
		for (k = 0; k < 32; k++)
			X[k] ^= V[j + k];
		xor_salsa8(&X[0], &X[16]);
		xor_salsa8(&X[16], &X[0]);
	}

	for (k = 0; k < 32; k++)
		le32enc(&B[4 * k], X[k]);

	PBKDF2_SHA256((const uint8_t *)input, 80, B, 128, 1, (uint8_t *)output, 32);
}

#if defined(USE_SSE2)
// By default, set to generic scrypt function. This will prevent crash in case when scrypt_detect_sse2() wasn't called
void (*scrypt_1024_1_1_256_sp_detected)(const char *input, char *output, char *scratchpad) = &scrypt_1024_1_1_256_sp_generic;

void scrypt_detect_sse2()
{
#if defined(USE_SSE2_ALWAYS)
    printf("scrypt: using scrypt-sse2 as built.\n");
#else // USE_SSE2_ALWAYS
    // 32bit x86 Linux or Windows, detect cpuid features
    unsigned int cpuid_edx=0;
#if defined(_MSC_VER)
    // MSVC
    int x86cpuid[4];
    __cpuid(x86cpuid, 1);
    cpuid_edx = (unsigned int)buffer[3];
#else // _MSC_VER
    // Linux or i686-w64-mingw32 (gcc-4.6.3)
    unsigned int eax, ebx, ecx;
    __get_cpuid(1, &eax, &ebx, &ecx, &cpuid_edx);
#endif // _MSC_VER

    if (cpuid_edx & 1<<26)
    {
        scrypt_1024_1_1_256_sp_detected = &scrypt_1024_1_1_256_sp_sse2;
        printf("scrypt: using scrypt-sse2 as detected.\n");
    }
    else
    {
        scrypt_1024_1_1_256_sp_detected = &scrypt_1024_1_1_256_sp_generic;
        printf("scrypt: using scrypt-generic, SSE2 unavailable.\n");
    }
#endif // USE_SSE2_ALWAYS
}
#endif

void scrypt_1024_1_1_256(const char *input, char *output)
{
	char scratchpad[SCRYPT_SCRATCHPAD_SIZE];
    scrypt_1024_1_1_256_sp(input, output, scratchpad);
}


void fastcyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
uint32_t ccc;
uint32_t ddd;
uint32_t i;
uint32_t point;
uint32_t lar;



for (i=0; i <32; i++) {
point=hash[i];

lar=point&3;
if (lar>1){lar^=18;}
cc=((cc<<8)|(cc>>7))&32767;
dd=((dd<<8)|(dd>>9))&131071;
ccc=cc<<24;
ddd=dd<<24;
cc^=(ccc>>23)^((ccc>>21)&(ddd>>21));
dd^=(ddd>>21)^(ccc>>23);
cc^=lar<<2;
point=(point>>2);

lar=point&3;
if (lar>1){lar^=18;}
cc=((cc<<8)|(cc>>7))&32767;
dd=((dd<<8)|(dd>>9))&131071;
ccc=cc<<24;
ddd=dd<<24;
cc^=(ccc>>23)^((ccc>>21)&(ddd>>21));
dd^=(ddd>>21)^(ccc>>23);
cc^=lar<<2;
point=(point>>2);

lar=point&3;
if (lar>1){lar^=18;}
cc=((cc<<8)|(cc>>7))&32767;
dd=((dd<<8)|(dd>>9))&131071;
ccc=cc<<24;
ddd=dd<<24;
cc^=(ccc>>23)^((ccc>>21)&(ddd>>21));
dd^=(ddd>>21)^(ccc>>23);
cc^=lar<<2;
point=(point>>2);

lar=point&3;
if (lar>1){lar^=18;}
cc=((cc<<8)|(cc>>7))&32767;
dd=((dd<<8)|(dd>>9))&131071;
ccc=cc<<24;
ddd=dd<<24;
cc^=(ccc>>23)^((ccc>>21)&(ddd>>21));
dd^=(ddd>>21)^(ccc>>23);
cc^=lar<<2;
point=(point>>2);

}

}

void cyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
uint32_t i;
uint32_t j;
uint32_t k;

for (i=0;i<32;i++){
for (j=0;j<8;j++){
for (k=0; k < 4; k++) {
cc=((cc<<1)|(cc>>14))&32767;
dd=((dd<<1)|(dd>>16))&131071;
if ((cc&1)==1){cc^=2; dd^=2;
}
if ((dd&1)==1){
dd^=8;
}
if (((cc&1)==1)&&((dd&1)==1)){
cc^=8;
}
}
cc^=((hash[i]>>(j+1-2*(j%2)))&1)<<2;
}
}
}

void bcyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
bool cclist[15];
bool ddlist[17];
int i;
int j;
int k;
bool temp;


bool expandhash[256];

for (i=0;i<32;i++){
for (j=0;j<8;j++){
expandhash[8*i+j]=(hash[i]>>j)%2;
}
}

for (i=0;i<15;i++){
cclist[i]=(cc&&(1<<i))>>i;
}
for (i=0;i<17;i++){
ddlist[i]=(dd&&(1<<i))>>i;
}

for (i=0;i<256;i++){
for (j=0;j<4;j++){
temp=cclist[14];
for (k=14;k>0;k--){
cclist[k]=cclist[k-1];
}
cclist[0]=temp;

temp=ddlist[16];
for (k=16;k>0;k--){
ddlist[k]=ddlist[k-1];
}
ddlist[0]=temp;

cclist[1]^=cclist[0];
ddlist[1]^=cclist[0];
ddlist[3]^=ddlist[0];
cclist[3]^=(cclist[0]&&ddlist[0]);
}
cclist[2]^=expandhash[i];
}



cc=0;
dd=0;
for (i=0;i<15;i++){
cc^=cclist[i]<<i;
}
for (i=0;i<17;i++){
dd^=ddlist[i]<<i;
}
}


bool testequality(uint32_t cc,uint32_t oldcc,uint32_t dd,uint32_t olddd){
return ((cc&32640)==(oldcc&32640))&&((dd&130560)==(olddd&130560));
}

uint32_t hashspincc(uint32_t x){return (x<<17)>>17;}

uint32_t hashspindd(uint32_t x){return x>>15;}

uint32_t hashspinrecombine(uint32_t cc,uint32_t dd){
return cc+(dd<<15);
}


void bitrotate_forward(uint32_t &x, uint32_t &len) {
    uint32_t y = x;
    y += x;
    x -= y / 2;
    if (y >= uint32_t(pow(2, len))) {
        y -= uint32_t(pow(2, len)) - 1;
        assert(y % 2 > 0);
    }
    x ^= y;
    y ^= x;
    x ^= y;
    assert(y == 0);
}

void bitrotate_reverse(uint32_t &x, uint32_t &len) {
    uint32_t y = 0;
    x ^= y;
    y ^= x;
    x ^= y;
    if (y % 2 > 0) {
        y += uint32_t(pow(2, len)) - 1;
        assert(y >= uint32_t(pow(2, len)));
    }
    x += y / 2;
    y -= x;
    assert(y == x);
}

//I still need to test these functions further.

void hashspinlfsr_forward(uint32_t &cc, uint32_t &dd,unsigned char input[32]) {
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t jj = 0;
    uint32_t k = 0;
    uint32_t pp = 15;
    uint32_t qq = 17;
    assert(i == 0);
    while (!(i == 32)) {
        assert(j == 0);
        while (!(j == 4)) {
            assert(jj == 0);
            while (!(jj == 2)) {
                assert(k == 0);
                while (!(k == 4)) {
                    bitrotate_forward(cc, pp);
                    bitrotate_forward(dd, qq);
                    if ((cc & 1) != 0) {
                        cc ^= 2;
                        dd ^= 2;
                        assert((cc & 1) != 0);
                    }
                    if ((dd & 1) != 0) {
                        dd ^= 8;
                        assert((dd & 1) != 0);
                    }
                    if ((cc & 1) != 0 && (dd & 1) != 0) {
                        cc ^= 8;
                        assert((cc & 1) != 0 && (dd & 1) != 0);
                    }
                    k += 1;
                    assert(!(k == 0));
                }
                k ^= 4;
                if ((input[i] & uint32_t(pow(2, 2 * j + 1 - jj))) != 0) {
                    cc ^= 4;
                    assert((input[i] & uint32_t(pow(2, 2 * j + 1 - jj))) != 0);
                }
                jj += 1;
                assert(!(jj == 0));
            }
            jj ^= 2;
            j += 1;
            assert(!(j == 0));
        }
        j ^= 4;
        i += 1;
        assert(!(i == 0));
    }
    assert(qq == 17);
    assert(pp == 15);
    assert(k == 0);
    assert(jj == 0);
    assert(j == 0);
    assert(i == 32);
}

void hashspinlfsr_reverse(uint32_t &cc, uint32_t &dd, unsigned char input[32]) {
    uint32_t i = 32;
    uint32_t j = 0;
    uint32_t jj = 0;
    uint32_t k = 0;
    uint32_t pp = 15;
    uint32_t qq = 17;
    assert(i == 32);
    while (!(i == 0)) {
        i -= 1;
        j ^= 4;
        assert(j == 4);
        while (!(j == 0)) {
            j -= 1;
            jj ^= 2;
            assert(jj == 2);
            while (!(jj == 0)) {
                jj -= 1;
                if ((input[i] & uint32_t(pow(2, 2 * j + 1 - jj))) != 0) {
                    cc ^= 4;
                    assert((input[i] & uint32_t(pow(2, 2 * j + 1 - jj))) != 0);
                }
                k ^= 4;
                assert(k == 4);
                while (!(k == 0)) {
                    k -= 1;
                    if ((cc & 1) != 0 && (dd & 1) != 0) {
                        cc ^= 8;
                        assert((cc & 1) != 0 && (dd & 1) != 0);
                    }
                    if ((dd & 1) != 0) {
                        dd ^= 8;
                        assert((dd & 1) != 0);
                    }
                    if ((cc & 1) != 0) {
                        dd ^= 2;
                        cc ^= 2;
                        assert((cc & 1) != 0);
                    }
                    bitrotate_reverse(dd, qq);
                    bitrotate_reverse(cc, pp);
                    assert(!(k == 4));
                }
                assert(!(jj == 2));
            }
            assert(!(j == 4));
        }
        assert(!(i == 32));
    }
    assert(qq == 17);
    assert(pp == 15);
    assert(k == 0);
    assert(jj == 0);
    assert(j == 0);
    assert(i == 0);
}

void roundmap_forward(int *x, int *y) {
    int i = 14;
    int j = 16;
    assert(i == 14);
    while (!(i == 0)) {
        i -= 1;
        x[i] ^= x[(i + 1) % 15];
        x[(i + 1) % 15] ^= x[i];
        x[i] ^= x[(i + 1) % 15];
        assert(!(i == 14));
    }
    assert(j == 16);
    while (!(j == 0)) {
        j -= 1;
        y[j] ^= y[(j + 1) % 17];
        y[(j + 1) % 17] ^= y[j];
        y[j] ^= y[(j + 1) % 17];
        assert(!(j == 16));
    }
    x[1] ^= x[0];
    x[3] ^= x[0] & y[0];
    y[3] ^= y[0];
    y[1] ^= x[0];
    assert(j == 0);
    assert(i == 0);
}
void roundmap_reverse(int *x, int *y) {
    int i = 0;
    int j = 0;
    y[1] ^= x[0];
    y[3] ^= y[0];
    x[3] ^= x[0] & y[0];
    x[1] ^= x[0];
    assert(j == 0);
    while (!(j == 16)) {
        y[j] ^= y[(j + 1) % 17];
        y[(j + 1) % 17] ^= y[j];
        y[j] ^= y[(j + 1) % 17];
        j += 1;
        assert(!(j == 0));
    }
    assert(i == 0);
    while (!(i == 14)) {
        x[i] ^= x[(i + 1) % 15];
        x[(i + 1) % 15] ^= x[i];
        x[i] ^= x[(i + 1) % 15];
        i += 1;
        assert(!(i == 0));
    }
    assert(j == 16);
    assert(i == 14);
}

void basefunction_forward(int *hash, int *x, int *y) {
    int i = 0;
    int j = 0;
    assert(i == 0);
    while (!(i == 256)) {
        assert(j == 0);
        while (!(j == 4)) {
            j += 1;
            roundmap_forward(x, y);
            assert(!(j == 0));
        }
        j -= 4;
        x[2] ^= hash[i + 1 - 2 * i % 2];
        i += 1;
        assert(!(i == 0));
    }
    assert(j == 0);
    assert(i == 256);
}
void basefunction_reverse(int *hash, int *x, int *y) {
    int i = 256;
    int j = 0;
    assert(i == 256);
    while (!(i == 0)) {
        i -= 1;
        x[2] ^= hash[i + 1 - 2 * i % 2];
        j += 4;
        assert(j == 4);
        while (!(j == 0)) {
            roundmap_reverse(x, y);
            j -= 1;
            assert(!(j == 4));
        }
        assert(!(i == 256));
    }
    assert(j == 0);
    assert(i == 0);
}

void readoff_forward(int *x, int *y, int *w) {
    int i = 0;
    assert(i == 0);
    while (!(i == 8)) {
        w[i] ^= x[i + 7];
        i += 1;
        assert(!(i == 0));
    }
    i -= 8;
    assert(i == 0);
    while (!(i == 8)) {
        w[i + 8] ^= y[i + 9];
        i += 1;
        assert(!(i == 0));
    }
    assert(i == 8);
}
void readoff_reverse(int *x, int *y, int *w) {
    int i = 8;
    assert(i == 8);
    while (!(i == 0)) {
        i -= 1;
        w[i + 8] ^= y[i + 9];
        assert(!(i == 8));
    }
    i += 8;
    assert(i == 8);
    while (!(i == 0)) {
        i -= 1;
        w[i] ^= x[i + 7];
        assert(!(i == 8));
    }
    assert(i == 0);
}

void spreadfifteen_forward(int &x, int *y) {
    int s = 15;
    int i = 0;
    assert(i == 0);
    while (!(i == s)) {
        if ((x & int(pow(2, i))) != 0) {
            y[i] ^= 1;
            x ^= int(pow(2, i));
            assert(y[i] != 0);
        }
        i += 1;
        assert(!(i == 0));
    }
    assert(i == s);
    assert(s == 15);
}
void spreadfifteen_reverse(int &x, int *y) {
    int s = 15;
    int i = s;
    assert(i == s);
    while (!(i == 0)) {
        i -= 1;
        if (y[i] != 0) {
            x ^= int(pow(2, i));
            y[i] ^= 1;
            assert((x & int(pow(2, i))) != 0);
        }
        assert(!(i == s));
    }
    assert(i == 0);
    assert(s == 15);
}

void spreadseventeen_forward(int &x, int *y) {
    int s = 17;
    int i = 0;
    assert(i == 0);
    while (!(i == s)) {
        if ((x & int(pow(2, i))) != 0) {
            y[i] ^= 1;
            x ^= int(pow(2, i));
            assert(y[i] != 0);
        }
        i += 1;
        assert(!(i == 0));
    }
    assert(i == s);
    assert(s == 17);
}
void spreadseventeen_reverse(int &x, int *y) {
    int s = 17;
    int i = s;
    assert(i == s);
    while (!(i == 0)) {
        i -= 1;
        if (y[i] != 0) {
            x ^= int(pow(2, i));
            y[i] ^= 1;
            assert((x & int(pow(2, i))) != 0);
        }
        assert(!(i == s));
    }
    assert(i == 0);
    assert(s == 17);
}

void hashspread_forward(int *hashbytes, int *hashbits) {
    int i = 0;
    int j = 0;
    assert(i == 0);
    while (!(i == 32)) {
        assert(j == 0);
        while (!(j == 8)) {
            if ((hashbytes[i] & int(pow(2, j))) != 0) {
                hashbytes[i] ^= int(pow(2, j));
                hashbits[8 * i + j] ^= 1;
                assert(hashbits[8 * i + j] != 0);
            }
            j += 1;
            assert(!(j == 0));
        }
        j -= 8;
        i += 1;
        assert(!(i == 0));
    }
    assert(j == 0);
    assert(i == 32);
}
void hashspread_reverse(int *hashbytes, int *hashbits) {
    int i = 32;
    int j = 0;
    assert(i == 32);
    while (!(i == 0)) {
        i -= 1;
        j += 8;
        assert(j == 8);
        while (!(j == 0)) {
            j -= 1;
            if (hashbits[8 * i + j] != 0) {
                hashbits[8 * i + j] ^= 1;
                hashbytes[i] ^= int(pow(2, j));
                assert((hashbytes[i] & int(pow(2, j))) != 0);
            }
            assert(!(j == 8));
        }
        assert(!(i == 32));
    }
    assert(j == 0);
    assert(i == 0);
}

void bhashspinlfsr_forward(int &cc, int &dd, int *hash) {
    int cx[15] = {0};
    int dx[17] = {0};
    int hashbits[256] = {0};
    spreadfifteen_forward(cc, cx);
    spreadseventeen_forward(dd, dx);
    hashspread_forward(hash, hashbits);
    basefunction_forward(hashbits, cx, dx);
    hashspread_reverse(hash, hashbits);
    spreadseventeen_reverse(dd, dx);
    spreadfifteen_reverse(cc, cx);
}
void bhashspinlfsr_reverse(int &cc, int &dd, int *hash) {
    int cx[15] = {0};
    int dx[17] = {0};
    int hashbits[256] = {0};
    spreadfifteen_forward(cc, cx);
    spreadseventeen_forward(dd, dx);
    hashspread_forward(hash, hashbits);
    basefunction_reverse(hashbits, cx, dx);
    hashspread_reverse(hash, hashbits);
    spreadseventeen_reverse(dd, dx);
    spreadfifteen_reverse(cc, cx);
}

void hashspinfinal(const char *input,uint32_t x, char *output){

unsigned char hash[40];
int i;

SHA256_CTX sha256;
SHA256_Init(&sha256);
SHA256_Update(&sha256,input,76);
SHA256_Final(hash,&sha256);

uint32_t cc=hashspincc(x);
uint32_t dd=hashspindd(x);
uint32_t newcc=cc;
uint32_t newdd=dd;

cyclelfsr(hash,newcc,newdd);

uint32_t y=hashspinrecombine(newcc,newdd);

hash[32]=255&x;
hash[33]=255&(x>>8);
hash[34]=255&(x>>16);
hash[35]=255&(x>>24);
hash[36]=255&y;
hash[37]=255&(y>>8);
hash[38]=255&(y>>16);
hash[39]=255&(y>>24);


unsigned char nexthash[32];

if (testequality(cc,newcc,dd,newdd)){
SHA256_Init(&sha256);
SHA256_Update(&sha256,hash,40);
SHA256_Final(nexthash,&sha256);
}
else {
for (i=0;i<32;i++){
nexthash[i]=231;
}
}

memcpy(output,&nexthash,32);

}


void revcyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
int i;
int j;
int k;

for (i=31;i>=0;i--){
for (j=7;j>=0;j--){
cc^=((hash[i]>>(j+1-2*(j%2)))&1)<<2;
for (k=3;k>=0;k--){


if ((cc&1)==1){cc^=2; dd^=2;
}
if ((dd&1)==1){
dd^=8;
}
if (((cc&1)==1)&&((dd&1)==1)){
cc^=8;
}
cc=((cc<<14)|(cc>>1))&32767;
dd=((dd<<16)|(dd>>1))&131071;

}
}
}

}


