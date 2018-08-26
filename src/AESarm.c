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

#pragma mark - Key Management 128
static inline uint32x4_t aes_128_expAssist(uint32x4_t prev, uint32_t rcon) {
	uint32x4_t round;
	round[0] = sub_word(rot_word( prev[3])) ^ rcon ^ prev[0];
	round[1] = sub_word(rot_word(round[0])) ^ rcon ^ prev[1];
	round[2] = sub_word(rot_word(round[1])) ^ rcon ^ prev[2];
	round[3] = sub_word(rot_word(round[2])) ^ rcon ^ prev[3];

	return veorq_u32(round, prev);
}

static void key_expansion_128(uint32x4_t * schedule[11], uint8x16_t encKey) {
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

static void key_expansion_192(uint32x4_t * schedule[13], uint8x16_t encKey) {
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

#pragma mark - Key Management 256
static inline uint32x4_t[2] aes_256_expAssist(uint32x4_t prev1, uint32x4_t prev2, uint32_t rcon) {
	uint32x4_t round1, round2;

	round1[0] = sub_word(rot_word( prev2[3])) ^ rcon ^ prev1[0];
	round1[1] = sub_word(rot_word(round1[0])) ^ rcon ^ prev1[1];
	round1[2] = sub_word(rot_word(round1[3])) ^ rcon ^ prev1[2];
	round1[3] = sub_word(rot_word(round1[3])) ^ rcon ^ prev1[3];

	round2[0] = sub_word(rot_word(round1[3])) ^ rcon ^ prev2[0];
	round2[1] = sub_word(rot_word(round2[3])) ^ rcon ^ prev2[1];
	round2[2] = sub_word(rot_word(round2[3])) ^ rcon ^ prev2[2];
	round2[3] = sub_word(rot_word(round2[3])) ^ rcon ^ prev2[3];

	return {round1, round2};
}

static void key_expansion_256(uint32x4_t * schedule[15], uint8x16_t encKey) {
	uint32x4_t doubleRound[2];

	schedule[ 0] = vld1q_u32(encKey);
	schedule[ 1] = vld1q_u32(encKey + 16);
	doubleRound  = aes_256_expAssist(schedule[ 0], schedule[ 1], 0x01);
	schedule[ 2] = doubleRound[0];
	schedule[ 3] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[ 2], schedule[ 3], 0x02);
	schedule[ 4] = doubleRound[0];
	schedule[ 5] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[ 4], schedule[ 5], 0x04);
	schedule[ 6] = doubleRound[0];
	schedule[ 7] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[ 6], schedule[ 7], 0x08);
	schedule[ 8] = doubleRound[0];
	schedule[ 9] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[ 8], schedule[ 9], 0x10);
	schedule[10] = doubleRound[0];
	schedule[11] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[10], schedule[11], 0x20);
	schedule[12] = doubleRound[0];
	schedule[13] = doubleRound[1];
	doubleRound  = aes_256_expAssist(schedule[12], schedule[13], 0x40);
	schedule[14] = doubleRound[0];
}

#pragma mark - Key Management Core
static inline uint32x4_t * load_key_expansion(uint8_t * key, AESKeyMode keymode) {
	uint32x4_t * keySchedule = malloc((keymode + 1) * sizeof(uint32x4));
	switch(keymode) {
		case aes_128:
			key_expansion_128(&keySchedule, vld1q_u8(key));
			break;
		case aes_192:
			key_expansion_192(&keySchedule, vld1q_u8(key));
			break;
		case aes_256:
			key_expansion_256(&keySchedule, vld1q_u8(key));
			break;
		default:
			fprintf(stderr, "[%s] %s", __FILE__, aes_mode_error());
			exit(EXIT_FAILURE);
			break;
	}

	return keySchedule;
}
