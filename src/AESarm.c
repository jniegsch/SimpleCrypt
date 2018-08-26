//
//  AESarm.c
//  
//
//  Created by Developer on 24.08.18.
//
// * * * * * * * * * * * * * * * * * * * *
// Compile with -march=armv8-a+crypto
// * * * * * * * * * * * * * * * * * * * *

#include "AESarm.h"

/*!
 @file AESarm.c
 
 The source file for the AES encryption (basic as well as CBC and CTR mode) implemented with Intel Intrinsics
 
 @updated 08-23-2018
 @compilerflag -fvisibility=hidden -march=armv8-a+crypto
 @version 0.0.1
 @author Jan Niegsch
 */

#pragma mark - Internal Core Definitions

#pragma mark - Internal Core
__attribute__((constructor))
static void initializer(void) {
	printf("[%s] initialized\n", __FILE__);
}

// destructor
__attribute__((destructor))
static void finalizer(void) {
	printf("[%s] finalized\n", __FILE__);
}

#pragma mark - Key Management Internals
typedef __attribute__((neon_vector_type(6))) uint32_t uint32x6_t;

uint8_t sBox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
}

uint8_t sBoxInv[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1c, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
}

static inline uint32_t sub_word(uint32_t inp) {
	uint8_t word[4];
	word[0] = sBox[(uint8_t)((inp & 0xff000000) >> 24)];
	word[1] = sBox[(uint8_t)((inp & 0x00ff0000) >> 16)];
	word[2] = sBox[(uint8_t)((inp & 0x0000ff00) >>  8)];
	word[3] = sBox[(uint8_t) (inp & 0x000000ff)];
	return *(uint32_t *)word;
}

static inline uint8_t[4] rot_word(uint32_t inp) {
	uint8_t popOff =(inp & 0xff000000) >> 24;
	uint32_t temp = (inp & 0x00ffffff) <<  8;
	return (temp + popOff);
}

#pragma mark - Key Management 128
static inline uint32x4_t aes_128_expAssist(uint32x4_t prev, uint32_t rcon) {
	uint32x4_t round;
	round[0] = sub_word(rot_word( prev[3])) ^ rcon ^ prev[0];
	round[1] = sub_word(rot_word(round[0])) ^ rcon ^ prev[1];
	round[2] = sub_word(rot_word(round[1])) ^ rcon ^ prev[2];
	round[3] = sub_word(rot_word(round[2])) ^ rcon ^ prev[3];

	return veorq_u32(round, prev);
}

static void key_expansion_128(uint32x4_t schedule[11], uint8x16_t encKey) {
	schedule[ 0] = vld1q_u32(encKey);
	schedule[ 1] = aes_128_expAssist(schedule[0], 0x01);
	schedule[ 2] = aes_128_expAssist(schedule[1], 0x02);
	schedule[ 3] = aes_128_expAssist(schedule[2], 0x04);
	schedule[ 4] = aes_128_expAssist(schedule[3], 0x08);
	schedule[ 5] = aes_128_expAssist(schedule[4], 0x10);
	schedule[ 6] = aes_128_expAssist(schedule[5], 0x20);
	schedule[ 7] = aes_128_expAssist(schedule[6], 0x40);
	schedule[ 8] = aes_128_expAssist(schedule[7], 0x80);
	schedule[ 9] = aes_128_expAssist(schedule[8], 0x1b);
	schedule[10] = aes_128_expAssist(schedule[9], 0x36);
}

#pragma mark - Key Management 192
static inline uint32x4_t[3] aes_192_expAssist(uint32x4_t prev, uint32x2_t * temp, uint32_t rcon1, uint32_t rcon2) {
	uint32x4_t round1, round2, round3;
	 
	round1[ 0] = (*temp)[0];
	round1[ 1] = (*temp)[1];
	round1[ 2] = sub_word(rot_word( round1[1])) ^ rcon1 ^   prev[0];
	round1[ 3] = sub_word(rot_word( round1[2])) ^ rcon1 ^   prev[1];

	round2[ 0] = sub_word(rot_word( round1[3])) ^ rcon1 ^   prev[2];
	round2[ 1] = sub_word(rot_word( round2[0])) ^ rcon1 ^   prev[3];
	round2[ 2] = sub_word(rot_word( round2[1])) ^ rcon1 ^ round1[0];
	round2[ 3] = sub_word(rot_word( round2[2])) ^ rcon1 ^ round1[1];

	round3[ 0] = sub_word(rot_word( round2[3])) ^ rcon2 ^ round1[2];
	round3[ 1] = sub_word(rot_word( round3[0])) ^ rcon2 ^ round1[3];
	round3[ 2] = sub_word(rot_word( round3[1])) ^ rcon2 ^ round2[0];
	round3[ 3] = sub_word(rot_word( round3[2])) ^ rcon2 ^ round2[1];
	
	(*temp)[0] = sub_word(rot_word( round3[3])) ^ rcon2 ^ round2[2];
	(*temp)[1] = sub_word(rot_word((*temp)[0])) ^ rcon2 ^ round2[3];

	return {round1, round2, round3};
}

static void key_expansion_192(uint32x4_t schedule[13], uint8x16_t encKey) {
	uint32x2_t temp;
	uint32x4_t trippleRounds[3];

	schedule[0]    = vld1q_u32(encKey);
	
	temp           = vld1_u32(encKey + 16);
	trippleRounds  = aes_192_expAssist(schedule[ 0], &temp, 0x01, 0x02);
	schedule[ 1]   = trippleRounds[0];
	schedule[ 2]   = trippleRounds[1];
	schedule[ 3]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist(schedule[ 0], &temp, 0x04, 0x08);
	schedule[ 4]   = trippleRounds[0];
	schedule[ 5]   = trippleRounds[1];
	schedule[ 6]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist(schedule[ 0], &temp, 0x10, 0x20);
	schedule[ 7]   = trippleRounds[0];
	schedule[ 8]   = trippleRounds[1];
	schedule[ 9]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist(schedule[ 0], &temp, 0x40, 0x80);
	schedule[10]   = trippleRounds[0];
	schedule[11]   = trippleRounds[1];
	schedule[12]   = trippleRounds[2];
}
