//
//  AESni.c
//  IIAES
//
//  Created by Developer on 23.08.18.
//  Copyright © 2018 jniegsch. All rights reserved.
//
// * * * * * * * * * * * * * * * * * * * * * * * * * *
// Compile with -fvisibility=hidden.
// * * * * * * * * * * * * * * * * * * * * * * * * * *
//

/*!
 @file AESni.c
 
 The source file for the AES encryption (basic as well as CBC and CTR mode) implemented with Intel Intrinsics
 
 @updated 08-23-2018
 @compilerflag -fvisibility=hidden -maes
 @version 0.0.1
 @author Jan Niegsch
 */

#include "AESni.h"

#pragma mark - Internal Core Definitions
/*!
 @define keygen_once_128
 Abstracts and cleans the key generation (expansion step) for AES-128 [1 step]
 */
#define keygen_once_128(i, p, rcon)\
			*schedule[i] = aes_128_expAssist(*schedule[p], _mm_aeskeygenassist_si128(*schedule[p], rcon))
/*!
 @define keygen_three_192
 Abstracts and cleans the key generation (expansion step) for AES-192 [three steps]
 */
#define keygen_three_192(i, rcon1, rcon2)\
			*schedule[i] = temp1;\
			*schedule[i+1] = temp3;\
			temp2 = _mm_aeskeygenassist_si128 (temp3, rcon1);\
			aes_192_expAssist(&temp1, &temp2, &temp3);\
			*schedule[i+1] = (__m128i)_mm_shuffle_pd((__m128d)*schedule[i+1], (__m128d)temp1,0);\
			*schedule[i+2] = (__m128i)_mm_shuffle_pd((__m128d)temp1, (__m128d)temp3, 1);\
			temp2 = _mm_aeskeygenassist_si128 (temp3, rcon2);\
			aes_192_expAssist(&temp1, &temp2, &temp3)
/*!
 @define keygen_twice_256
 Abstracts and cleans the key generation (expansion step) for AES-256 [2 steps]
 */
#define keygen_twice_256(i, rcon)\
			temp2 = _mm_aeskeygenassist_si128 (temp3, rcon);\
			aes_256_expAssist1(&temp1, &temp2);\
			*schedule[i] = temp1;\
			aes_256_expAssist2(&temp1, &temp3);\
			*schedule[i+1] = temp3

#pragma mark - Internal Core
// initializer
__attribute__((constructor))
static void initializer(void) {
	printf("[%s] initialized\n", __FILE__);
}

// destroctor
__attribute__((destructor))
static void finalizer(void) {
	printf("[%s] finalized\n", __FILE__);
}

#pragma mark - Key Management 128
static inline __m128i aes_128_expAssist(__m128i temp1, __m128i temp2) {
	__m128i temp3;
	temp2 = _mm_shuffle_epi32(temp2, 0xff);
	temp3 = _mm_slli_si128(temp1, 0x4);
	temp1 = _mm_xor_si128(temp1, temp3);
	temp3 = _mm_slli_si128(temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp3 = _mm_slli_si128 (temp3, 0x4);
	temp1 = _mm_xor_si128 (temp1, temp3);
	temp1 = _mm_xor_si128 (temp1, temp2);
	return temp1;
}

static void aes_128_key_expansion(__m128i ** schedule, uint8_t * encKey) {
	*schedule[0] = _mm_loadu_si128((const __m128i *) encKey);
	keygen_once_128( 1, 0, 0x01);
	keygen_once_128( 2, 1, 0x02);
	keygen_once_128( 3, 2, 0x04);
	keygen_once_128( 4, 3, 0x08);
	keygen_once_128( 5, 4, 0x10);
	keygen_once_128( 6, 5, 0x20);
	keygen_once_128( 7, 6, 0x40);
	keygen_once_128( 8, 7, 0x80);
	keygen_once_128( 9, 8, 0x1b);
	keygen_once_128(10, 9, 0x36);
}

#pragma mark - Key Management 192
static inline void aes_192_expAssist(__m128i * temp1, __m128i * temp2, __m128i * temp3) {
	__m128i temp4;
	*temp2 = _mm_shuffle_epi32 (*temp2, 0x55);
	temp4 = _mm_slli_si128 (*temp1, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	*temp1 = _mm_xor_si128 (*temp1, *temp2);
	*temp2 = _mm_shuffle_epi32(*temp1, 0xff);
	temp4 = _mm_slli_si128 (*temp3, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	*temp3 = _mm_xor_si128 (*temp3, *temp2);
}

static void aes_192_key_expansion(__m128i ** schedule, uint8_t * encKey) {
	__m128i temp1, temp2, temp3;
	
	temp1 = _mm_loadu_si128((__m128i *)encKey);
	temp3 = _mm_loadu_si128((__m128i *)(encKey + 16));
	
	keygen_three_192(0, 0x01, 0x02);
	keygen_three_192(3, 0x04, 0x08);
	keygen_three_192(6, 0x10, 0x20);
	keygen_three_192(9, 0x40, 0x80);
	*schedule[12] = temp1;
	
}
#pragma mark - Key Management 256
static inline void aes_256_expAssist1(__m128i * temp1, __m128i * temp2) {
	__m128i temp4;
	*temp2 = _mm_shuffle_epi32(*temp2, 0xff);
	temp4 = _mm_slli_si128 (*temp1, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp1 = _mm_xor_si128 (*temp1, temp4);
	*temp1 = _mm_xor_si128 (*temp1, *temp2);
}

static inline void aes_256_expAssist2(__m128i * temp1, __m128i * temp3) {
	__m128i temp2, temp4;
	temp4 = _mm_aeskeygenassist_si128 (*temp1, 0x0);
	temp2 = _mm_shuffle_epi32(temp4, 0xaa);
	temp4 = _mm_slli_si128 (*temp3, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	temp4 = _mm_slli_si128 (temp4, 0x4);
	*temp3 = _mm_xor_si128 (*temp3, temp4);
	*temp3 = _mm_xor_si128 (*temp3, temp2);
}

static void aes_256_key_expansion(__m128i ** schedule, uint8_t * encKey) {
	__m128i temp1, temp2, temp3;
	
	temp1 = _mm_loadu_si128((__m128i *)encKey);
	temp3 = _mm_loadu_si128((__m128i *)(encKey + 16));
	
	*schedule[0] = temp1;
	*schedule[1] = temp3;
	keygen_twice_256( 2, 0x01);
	keygen_twice_256( 4, 0x02);
	keygen_twice_256( 6, 0x04);
	keygen_twice_256( 8, 0x08);
	keygen_twice_256(10, 0x10);
	keygen_twice_256(12, 0x20);
	temp2 = _mm_aeskeygenassist_si128 (temp3, 0x40);
	aes_256_expAssist1(&temp1, &temp2);
	*schedule[14] = temp1;
}

#pragma mark - Key Management Core
static inline __m128i * load_key_expansion(uint8_t * key, AESKeyMode keymode) {
	__m128i * keySchedule = malloc((keymode + 1) * sizeof(__m128i));
	switch (keymode) {
		case aes_128:
			aes_128_key_expansion(&keySchedule, key);
			break;
			
		case aes_192:
			aes_192_key_expansion(&keySchedule, key);
			break;
			
		case aes_256:
			aes_256_key_expansion(&keySchedule, key);
			break;
			
		default:
			fprintf(stderr, "[%s] Fatal Error: an invalid aes mode was passed. \n                     > Even though Rijndael supports several lengths of key bits, AES is defined to only support 128, 192, or 256 bits.\n", __FILE__);
			exit(EXIT_FAILURE);
			break;
	}
	
	return keySchedule;
}

#pragma mark - Encryption and Decryption Core
inline void aes_ni_enc(__m128i * data, __m128i * key_schedule, AESKeyMode keymode) {
	*data = _mm_xor_si128(*data, key_schedule[0]);
	// unrolled for performance
	*data = _mm_aesenc_si128(*data, key_schedule[1]);
	*data = _mm_aesenc_si128(*data, key_schedule[2]);
	*data = _mm_aesenc_si128(*data, key_schedule[3]);
	*data = _mm_aesenc_si128(*data, key_schedule[4]);
	*data = _mm_aesenc_si128(*data, key_schedule[5]);
	*data = _mm_aesenc_si128(*data, key_schedule[6]);
	*data = _mm_aesenc_si128(*data, key_schedule[7]);
	*data = _mm_aesenc_si128(*data, key_schedule[8]);
	*data = _mm_aesenc_si128(*data, key_schedule[9]);
	if (keymode > 10) {
		*data = _mm_aesenc_si128(*data, key_schedule[10]);
		*data = _mm_aesenc_si128(*data, key_schedule[11]);
		if (keymode > 12) {
			*data = _mm_aesenc_si128(*data, key_schedule[12]);
			*data = _mm_aesenc_si128(*data, key_schedule[13]);
		}
	}
	*data = _mm_aesenclast_si128(*data, key_schedule[keymode]);
}

inline void aes_ni_dec(__m128i * data, __m128i * key_schedule, AESKeyMode keymode) {
	*data = _mm_xor_si128(*data, key_schedule[keymode]);
	// unrolled for performance
	if (keymode > 12) {
		*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[13]));
		*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[12]));
	}
	if (keymode > 10) {
		*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[11]));
		*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[10]));
	}
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[9]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[8]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[7]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[6]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[5]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[4]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[3]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[2]));
	*data = _mm_aesdec_si128(*data, _mm_aesimc_si128(key_schedule[1]));
	*data = _mm_aesdeclast_si128(*data, key_schedule[0]);
}

#pragma mark - CBC Core
void aes_cbc_ni_enc(uint8_t * inpt,
					uint8_t * outt,
					uint8_t * ivec,
					unsigned long mlength,
					uint8_t * epoch_key,
					AESKeyMode keymode) {
	__m128i feedback, data;
	
	
	
	if (mlength % 16) {
		mlength = mlength / 16 + 1;
	} else {
		mlength /= 16;
	}
	
	__m128i * key_sched = load_key_expansion(epoch_key, keymode);
	
	feedback = _mm_loadu_si128((__m128i *)ivec);
	for (size_t i = 0; i < mlength; i++) {
		data = _mm_loadu_si128(&((__m128i *)inpt)[i]);
		feedback = _mm_xor_si128(data, feedback);
		aes_ni_enc(&feedback, key_sched, keymode);
		_mm_storeu_si128(&((__m128i *)outt)[i], feedback);
	}
}

void aes_cbc_ni_dec(uint8_t * inpt,
					uint8_t * outt,
					uint8_t * ivec,
					unsigned long clength,
					uint8_t * epoch_key,
					AESKeyMode keymode) {
	__m128i feedback, data, last_in;
	
	if (clength % 16) {
		clength = clength / 16 + 1;
	} else {
		clength /= 16;
	}
	
	__m128i * key_sched = load_key_expansion(epoch_key, keymode);
	
	feedback = _mm_loadu_si128((__m128i *) ivec);
	for (size_t i = 0; i < clength; i++) {
		last_in = _mm_loadu_si128(&((__m128i *)inpt)[i]);
		data = last_in;
		aes_ni_dec(&data, key_sched, keymode);
		data = _mm_xor_si128(data, feedback);
		_mm_storeu_si128(&((__m128i *)outt)[i], data);
		feedback = last_in;
	}
}

#pragma mark - CTR Core
void aes_ctr_ni(uint8_t * inpt,
				uint8_t * outt,
				uint8_t * ivec,
				unsigned long mlength,
				uint8_t * epoch_key,
				AESKeyMode keymode) {
	__m128i iv, feedback, data, ONE;
	
	if (mlength % 16) {
		mlength = mlength / 16 + 1;
	} else {
		mlength /= 16;
	}
	
	__m128i * key_sched = load_key_expansion(epoch_key, keymode);
	
	ONE =  _mm_set_epi8(1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);
	
	iv = _mm_loadu_si128((__m128i *) ivec);
	for (size_t i = 0; i < mlength; i++) {
		if (i != 0)
			iv = _mm_add_epi8(iv, ONE);
		feedback = iv;
		aes_ni_enc(&feedback, key_sched, keymode);
		data = _mm_xor_si128(feedback, _mm_loadu_si128(&((__m128i *)inpt)[i]));
		_mm_storeu_si128(&((__m128i *)outt)[i], data);
	}
}
