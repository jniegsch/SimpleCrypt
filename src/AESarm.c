//
//  AESarm.c
//  SimpleCrypt
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
	uint32_t round[4], prv[4];
	// load neon vector type into array
	vst1q_32(prv, prev);

	round[0] = sub_word(rot_word(  prv[3])) ^ rcon ^ prv[0];
	round[1] = sub_word(rot_word(round[0])) ^ rcon ^ prv[1];
	round[2] = sub_word(rot_word(round[1])) ^ rcon ^ prv[2];
	round[3] = sub_word(rot_word(round[2])) ^ rcon ^ prv[3];

	return vld1q_u3(round);
}

static void key_expansion_128(uint32x4_t * schedule[11], uint8x16_t encKey) {
	(*schedule)[ 0] = vld1q_u32(encKey);
	(*schedule)[ 1] = aes_128_expAssist((*schedule)[0], 0x01);
	(*schedule)[ 2] = aes_128_expAssist((*schedule)[1], 0x02);
	(*schedule)[ 3] = aes_128_expAssist((*schedule)[2], 0x04);
	(*schedule)[ 4] = aes_128_expAssist((*schedule)[3], 0x08);
	(*schedule)[ 5] = aes_128_expAssist((*schedule)[4], 0x10);
	(*schedule)[ 6] = aes_128_expAssist((*schedule)[5], 0x20);
	(*schedule)[ 7] = aes_128_expAssist((*schedule)[6], 0x40);
	(*schedule)[ 8] = aes_128_expAssist((*schedule)[7], 0x80);
	(*schedule)[ 9] = aes_128_expAssist((*schedule)[8], 0x1b);
	(*schedule)[10] = aes_128_expAssist((*schedule)[9], 0x36);
}

#pragma mark - Key Management 192
static inline uint32x4_t * aes_192_expAssist(uint32x4_t prev, uint32x2_t * temp, uint32_t rcon1, uint32_t rcon2) {
	uint32_t round1[4], round2[4], round3[4], tmp[2], prv[4];

	vst1_u32(tmp, *temp);
	vst1q_u32(prv, prev);
	 
	round1[ 0] = tmp[0];
	round1[ 1] = tmp[1];
	round1[ 2] = sub_word(rot_word( round1[1])) ^ rcon1 ^    prv[0];
	round1[ 3] = sub_word(rot_word( round1[2])) ^ rcon1 ^    prv[1];

	round2[ 0] = sub_word(rot_word( round1[3])) ^ rcon1 ^    prv[2];
	round2[ 1] = sub_word(rot_word( round2[0])) ^ rcon1 ^    prv[3];
	round2[ 2] = sub_word(rot_word( round2[1])) ^ rcon1 ^ round1[0];
	round2[ 3] = sub_word(rot_word( round2[2])) ^ rcon1 ^ round1[1];

	round3[ 0] = sub_word(rot_word( round2[3])) ^ rcon2 ^ round1[2];
	round3[ 1] = sub_word(rot_word( round3[0])) ^ rcon2 ^ round1[3];
	round3[ 2] = sub_word(rot_word( round3[1])) ^ rcon2 ^ round2[0];
	round3[ 3] = sub_word(rot_word( round3[2])) ^ rcon2 ^ round2[1];
	
	    tmp[0] = sub_word(rot_word( round3[3])) ^ rcon2 ^ round2[2];
	    tmp[1] = sub_word(rot_word(    tmp[0])) ^ rcon2 ^ round2[3];

	uint32x4_t expansion[3] = {vld1q_u3(round1), vld1q_u3(round2), vld1q_u3(round3)};

	return expansion;
}

static void key_expansion_192(uint32x4_t * schedule[13], uint8x16_t encKey) {
	uint32x2_t temp;
	uint32x4_t * trippleRounds = NULL;

	(*schedule)[0]    = vld1q_u32(encKey);
	temp           = vld1_u32(encKey + 16);
	trippleRounds  = aes_192_expAssist((*schedule)[0], &temp, 0x01, 0x02);
	(*schedule)[ 1]   = trippleRounds[0];
	(*schedule)[ 2]   = trippleRounds[1];
	(*schedule)[ 3]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist((*schedule)[3], &temp, 0x04, 0x08);
	(*schedule)[ 4]   = trippleRounds[0];
	(*schedule)[ 5]   = trippleRounds[1];
	(*schedule)[ 6]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist((*schedule)[6], &temp, 0x10, 0x20);
	(*schedule)[ 7]   = trippleRounds[0];
	(*schedule)[ 8]   = trippleRounds[1];
	(*schedule)[ 9]   = trippleRounds[2];
	trippleRounds  = aes_192_expAssist((*schedule)[9], &temp, 0x40, 0x80);
	(*schedule)[10]   = trippleRounds[0];
	(*schedule)[11]   = trippleRounds[1];
	(*schedule)[12]   = trippleRounds[2];
}

#pragma mark - Key Management 256
static inline uint32x4_t * aes_256_expAssist(uint32x4_t prev1, uint32x4_t prev2, uint32_t rcon) {
	uint32_t round1[4], round2[4], prv1[4], prv2[4];

	vst1q_u32(prv1, prev1);
	vst1q_u32(prv2, prev2);

	round1[0] = sub_word(rot_word(  prv2[3])) ^ rcon ^ prv1[0];
	round1[1] = sub_word(rot_word(round1[0])) ^ rcon ^ prv1[1];
	round1[2] = sub_word(rot_word(round1[3])) ^ rcon ^ prv1[2];
	round1[3] = sub_word(rot_word(round1[3])) ^ rcon ^ prv1[3];

	round2[0] = sub_word(rot_word(round1[3])) ^ rcon ^ prv2[0];
	round2[1] = sub_word(rot_word(round2[3])) ^ rcon ^ prv2[1];
	round2[2] = sub_word(rot_word(round2[3])) ^ rcon ^ prv2[2];
	round2[3] = sub_word(rot_word(round2[3])) ^ rcon ^ prv2[3];

	uint32x4_t expansion[2] = {vld1q_u3(round1), vld1q_u3(round2)};

	return expansion;
}

static void key_expansion_256(uint32x4_t * schedule[15], uint8x16_t encKey) {
	uint32x4_t * doubleRound = NULL;

	(*schedule)[ 0] = vld1q_u32(encKey);
	(*schedule)[ 1] = vld1q_u32(encKey + 16);
	doubleRound     = aes_256_expAssist((*schedule)[ 0], (*schedule)[ 1], 0x01);
	(*schedule)[ 2] = doubleRound[0];
	(*schedule)[ 3] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[ 2], (*schedule)[ 3], 0x02);
	(*schedule)[ 4] = doubleRound[0];
	(*schedule)[ 5] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[ 4], (*schedule)[ 5], 0x04);
	(*schedule)[ 6] = doubleRound[0];
	(*schedule)[ 7] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[ 6], (*schedule)[ 7], 0x08);
	(*schedule)[ 8] = doubleRound[0];
	(*schedule)[ 9] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[ 8], (*schedule)[ 9], 0x10);
	(*schedule)[10] = doubleRound[0];
	(*schedule)[11] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[10], (*schedule)[11], 0x20);
	(*schedule)[12] = doubleRound[0];
	(*schedule)[13] = doubleRound[1];
	doubleRound     = aes_256_expAssist((*schedule)[12], (*schedule)[13], 0x40);
	(*schedule)[14] = doubleRound[0];
}

#pragma mark - Key Management Core
inline uint32x4_t * load_key_expansion(uint8_t * key, AESKeyMode keymode) {
	uint32x4_t * keySchedule = malloc((keymode + 1) * sizeof(uint32x4_t));
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

#pragma mark - Encryption and Decryption Core
inline void aes_arm_enc(uint8x16_t * data, uint8x16_t * keySchedule, AESKeyMode keymode) {
	*data = veorq_u8(*data, keySchedule[ 0]);
	//			 mix cols		encrypt
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[1]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[2]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[3]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[4]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[5]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[6]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[7]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[8]));
	*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[9]));
	if (keymode > 10) {
		*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[10]));
		*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[11]));
		if (keymode > 12) {
			*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[12]));
			*data = vaesmcq_u8(vaeseq_u8(*data, (uint8x16_t)keySchedule[13]));
		}
	}
	*data = vaeseq_u8(*data, keySchedule[keymode]);
}

inline void aes_arm_dec(uint8x16_t * data, uint8x16_t * keySchedule, AESKeyMode keymode) {
	*data = veorq_u8(*data, keySchedule[keymode]);
	if (keymode > 12) {
		*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[13]));
		*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[12]));
	}
	if (keymode > 10) {
		*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[11]));
		*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[10]));
	}
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 9]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 8]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 7]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 6]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 5]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 4]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 3]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 2]));
	*data = vaesimcq_u8(vaesdq_u8(*data, (uint8x16_t)keySchedule[ 1]));
	*data = vaesdq_u8(*data, (uint8x16_t)keySchedule[0]);
}

#pragma mark - CBC Core
void aes_cbc_arm_enc(uint8_t * input, uint8_t * output, uint8_t * ivec, unsigned long mlength, uint8_t * epochKey, AESKeyMode keymode) {
	uint8x16_t feedback, data;

	// check message length
	if (mlength % 16) {
		mlength = mlength / 16 + 1;
	} else {
		mlength /= 16;
	}

	// key exp
	uint32x4_t * keySched = load_key_expansion(epochKey, keymode);
	feedback = vld1q_u8((uint8x16_t *)ivec);
	for (size_t i = 0; i < mlength; i++) {
		data = vld1q_u8(&input[i * 16]);
		feedback = veor_u8(data, feedback);
		aes_arm_enc(&feedback, keySched, keymode);
		vst1q_u8(&output[i * 16], feedback);
	}
}

void aes_cbc_arm_dec(uint8_t * input, uint8_t * output, uint8_t * ivec, unsigned long mlength, uint8_t * epochKey, AESKeyMode keymode) {
	uint8x16_t feedback, data, lastIn;

	// check message length
	if (mlength % 16) {
		mlength = mlength / 16 + 1;
	} else {
		mlength /= 16;
	}

	// key exp
	uint32x4_t * keySched = load_key_expansion(epochKey, keymode);
	feedback = vld1q_u8(ivec);
	for (size_t i = 0; i < mlength; i++) {
		data = vld1q_u8(&input[i * 16]);
		lastIn = data;
		aes_arm_enc(&data, keySched, keymode);
		data = veor_u8(data, feedback);
		vst1q_u8(&output[i * 16], data);
		feedback = lastIn;
	}
}

#pragma mark - CTR Core
void aes_ctr_arm(uint8_t * input, uint8_t * output, uint8_t * ivec, unsigned long mlength, uint8_t * epochKey, AESKeyMode keymode) {
	uint8x16_t iv, feedback, data, ONE;

	if (mlength % 16) {
		mlength = mlength / 16 + 1;
	} else {
		mlength /= 16;
	}

	uint32x4_t * keySched = load_key_expansion(epochKey, keymode);

	iv = vld1q_u8(ivec);
	uint8_t one = 1;
	ONE = vld1q_dup_u8(&one);

	for (size_t i = 0; i < mlength; i++) {
		if (i != 0) {
			iv = vaddq_u8(iv, ONE);
		}
		feedback = iv;
		aes_arm_enc(&feedback, keySched, keymode);
		data = veor_u8(feedback, vld1q_u8(&(input[i * 16])));
		vst1q_u8(&(input[i * 16]), data);
	}
}
