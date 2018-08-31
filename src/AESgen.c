//
//  AESni.c
//  SimpleCrypt
//
//  Created by Developer on 31.08.18.
//  Copyright © 2018 jniegsch. All rights reserved.
//
// * * * * * * * * * * * * * * * * * * * * * * * * * *
// Compile with -fvisibility=hidden.
// * * * * * * * * * * * * * * * * * * * * * * * * * *
//

/*!
 @file AESgen.c
 
 The source file for the AES encryption (basic as well as CBC and CTR mode) implemented in general c
 
 @updated 08-31-2018
 @compilerflag -fvisibility=hidden
 @version 0.0.1
 @author Jan Niegsch
 */

#include "AESgen.h"

#pragma mark - Preprocessor Definitions
#define nextThree(a, b, c) \
      ns[0] = (*schedule)[ 1]; \
      ns[1] = (*schedule)[ 2]; \
      ns[2] = (*schedule)[ 3]

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

#pragma mark - Internal Converters
static inline uint32x4 u8x16_u32x4(uint8x16 x) {
  uint32x4 ret;
  ret._[0] = (uint32_t)(((uint32_t) x._[ 0]) << 24) + (((uint32_t) x._[ 1]) << 16) + (((uint32_t) x._[ 2]) << 8) + ((uint32_t) x._[ 3]);
  ret._[1] = (uint32_t)(((uint32_t) x._[ 4]) << 24) + (((uint32_t) x._[ 5]) << 16) + (((uint32_t) x._[ 6]) << 8) + ((uint32_t) x._[ 7]);
  ret._[2] = (uint32_t)(((uint32_t) x._[ 8]) << 24) + (((uint32_t) x._[ 9]) << 16) + (((uint32_t) x._[10]) << 8) + ((uint32_t) x._[11]);
  ret._[3] = (uint32_t)(((uint32_t) x._[12]) << 24) + (((uint32_t) x._[13]) << 16) + (((uint32_t) x._[14]) << 8) + ((uint32_t) x._[15]);
  return ret;
}

static inline uint32x2 u8x16_u32x2(uint8x16 x) {
  uint32x2 ret;
  ret._[0] = (uint32_t)(((uint32_t) x._[ 0]) << 24) + (((uint32_t) x._[ 1]) << 16) + (((uint32_t) x._[ 2]) << 8) + ((uint32_t) x._[ 3]);
  ret._[1] = (uint32_t)(((uint32_t) x._[ 4]) << 24) + (((uint32_t) x._[ 5]) << 16) + (((uint32_t) x._[ 6]) << 8) + ((uint32_t) x._[ 7]);
  return ret;
}

#pragma mark - Key Management: 128
static inline void __gen_aes_128_expAssist(uint32x4 nextRound, uint32_t rcon, uint32x4 prevRound) {
  nextRound._[0] = sub_word(rot_word(prevRound._[3])) ^ rcon ^ prevRound._[0];
  nextRound._[1] = sub_word(rot_word(nextRound._[0])) ^ rcon ^ prevRound._[1];
  nextRound._[2] = sub_word(rot_word(nextRound._[0])) ^ rcon ^ prevRound._[2];
  nextRound._[3] = sub_word(rot_word(nextRound._[0])) ^ rcon ^ prevRound._[3];
}

static void __gen_key_expansion_128(uint32x4 * schedule[11], uint8x16 encKey) {
  (*schedule)[0] = u8x16_u32x4(encKey);
  __gen_aes_128_expAssist((*schedule)[ 1], 0x01, (*schedule)[0]);
  __gen_aes_128_expAssist((*schedule)[ 2], 0x02, (*schedule)[1]);
  __gen_aes_128_expAssist((*schedule)[ 3], 0x04, (*schedule)[2]);
  __gen_aes_128_expAssist((*schedule)[ 4], 0x08, (*schedule)[3]);
  __gen_aes_128_expAssist((*schedule)[ 5], 0x10, (*schedule)[4]);
  __gen_aes_128_expAssist((*schedule)[ 6], 0x20, (*schedule)[5]);
  __gen_aes_128_expAssist((*schedule)[ 7], 0x40, (*schedule)[6]);
  __gen_aes_128_expAssist((*schedule)[ 8], 0x80, (*schedule)[7]);
  __gen_aes_128_expAssist((*schedule)[ 9], 0x1b, (*schedule)[8]);
  __gen_aes_128_expAssist((*schedule)[10], 0x36, (*schedule)[9]);
}

#pragma mark - Key Management: 192
static inline void __gen_aes_192_expAssist(uint32x4 nextThreeRounds[3], uint32x4 prevRound, uint32x2 * temp, uint32_t rcon1, uint32_t rcon2) {
  nextThreeRounds[0]._[0] = temp->_[0];
  nextThreeRounds[0]._[1] = temp->_[1];
  nextThreeRounds[0]._[2] = sub_word(rot_word(nextThreeRounds[0]._[1])) ^ rcon1 ^          prevRound._[0];
  nextThreeRounds[0]._[3] = sub_word(rot_word(nextThreeRounds[0]._[2])) ^ rcon1 ^          prevRound._[1];

  nextThreeRounds[1]._[0] = sub_word(rot_word(nextThreeRounds[0]._[3])) ^ rcon1 ^          prevRound._[2];
  nextThreeRounds[1]._[1] = sub_word(rot_word(nextThreeRounds[1]._[0])) ^ rcon1 ^          prevRound._[3];
  nextThreeRounds[1]._[2] = sub_word(rot_word(nextThreeRounds[1]._[1])) ^ rcon1 ^ nextThreeRounds[0]._[0];
  nextThreeRounds[1]._[3] = sub_word(rot_word(nextThreeRounds[1]._[2])) ^ rcon1 ^ nextThreeRounds[0]._[1];

  nextThreeRounds[2]._[0] = sub_word(rot_word(nextThreeRounds[1]._[3])) ^ rcon2 ^ nextThreeRounds[0]._[2];
  nextThreeRounds[2]._[1] = sub_word(rot_word(nextThreeRounds[2]._[0])) ^ rcon2 ^ nextThreeRounds[0]._[3];
  nextThreeRounds[2]._[2] = sub_word(rot_word(nextThreeRounds[2]._[1])) ^ rcon2 ^ nextThreeRounds[1]._[0];
  nextThreeRounds[2]._[3] = sub_word(rot_word(nextThreeRounds[2]._[2])) ^ rcon2 ^ nextThreeRounds[1]._[1];

  temp->_[0] =              sub_word(rot_word(nextThreeRounds[2]._[3])) ^ rcon2 ^ nextThreeRounds[1]._[2];
  temp->_[1] =              sub_word(rot_word(             temp->_[0])) ^ rcon2 ^ nextThreeRounds[1]._[3];
}

static void __gen_key_expansion_192(uint32x4 * schedule[13], uint8x16 * encKey) {
  uint32x2 temp; uint32x4 ns[3];
  
  (*schedule)[0] = u8x16_u32x4(encKey[0]);
  temp = u8x16_u32x2(encKey[1]);

  nextThree( 1,  2,  3);
  __gen_aes_192_expAssist(ns, (*schedule)[0], &temp, 0x01, 0x02);
  nextThree( 4,  5,  6);
  __gen_aes_192_expAssist(ns, (*schedule)[0], &temp, 0x04, 0x08);
  nextThree( 7,  8,  9);
  __gen_aes_192_expAssist(ns, (*schedule)[0], &temp, 0x10, 0x20);
  nextThree(10, 11, 12);
  __gen_aes_192_expAssist(ns, (*schedule)[0], &temp, 0x40, 0x80);
}
