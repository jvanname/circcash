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
/*
#include "scrypt.h"
#include "util.h"
*/
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <iostream>

using namespace std;

void fastcyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
uint32_t ccc;
uint32_t ddd;
uint32_t i;
uint32_t j;
uint32_t point;
uint32_t lar;



for (i=0; i <32; i++) {
point=hash[i];
for (j=0; j <4;j++) {

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



void bcyclelfsr(unsigned char hash[32],uint32_t &cc,uint32_t &dd){
bool cclist[15];
bool ddlist[17];
int i;
int j;
int k;
bool temp;


bool expandhash[256];

for (i=0;i<32;i++){
for (j=0;j<4;j++){
for (k=0;k<2;k++){
expandhash[8*i+2*j+k]=(hash[i]>>(2*j+1-k))%2;
}
}
}

for (i=0;i<15;i++){
cclist[i]=(cc&(1<<i))>>i;
}
for (i=0;i<17;i++){
ddlist[i]=(dd&(1<<i))>>i;
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

/*
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

fastcyclelfsr(hash,newcc,newdd);

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
SHA256_Update(&sha256,hash,40);0
SHA256_Final(nexthash,&sha256);
}
else {
for (i=0;i<32;i++){
nexthash[i]=231;
}
}

memcpy(output,&nexthash,32);

}
*/


int main(){
unsigned char hash[32];
unsigned int i;
int ii;
for (i=0;i<32;i++){hash[i]=137+i;}
uint32_t cc=40;
uint32_t dd=2;


cout<<cc<<endl;
cout<<dd<<endl;

for (ii=0;ii<100000;ii++){
hash[0]=ii%256;
hash[3]=ii%243;
cyclelfsr(hash,cc,dd);
}
for (ii=99999;ii>=0;ii--){
hash[0]=ii%256;
hash[3]=ii%243;
revcyclelfsr(hash,cc,dd);
}

cout<<cc<<endl;
cout<<dd<<endl;

}
