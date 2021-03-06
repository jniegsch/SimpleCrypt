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
#define prepareNextThree uint32x4 n[3]
#define nextThree(a, b, c) \
          n[0] = (*schedule)[a]; \
          n[1] = (*schedule)[b]; \
          n[2] = (*schedule)[c]

#define prepareNextAndPrevTwo uint32x4 n[2]; uint32x4 p[2]
#define nextTwo(a, b) \
          n[0] = (*schedule)[a]; \
          n[1] = (*schedule)[b]

#define prevTwo(a, b) \
          p[0] = (*schedule)[a]; \
          p[1] = (*schedule)[b]

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
static inline uint32x2 u8x16_u32x2(uint8x16 x) {
  uint32x2 ret;
  ret._[0] = (uint32_t)(((uint32_t) x._[ 0]) << 24) + (((uint32_t) x._[ 1]) << 16) + (((uint32_t) x._[ 2]) << 8) + ((uint32_t) x._[ 3]);
  ret._[1] = (uint32_t)(((uint32_t) x._[ 4]) << 24) + (((uint32_t) x._[ 5]) << 16) + (((uint32_t) x._[ 6]) << 8) + ((uint32_t) x._[ 7]);
  return ret;
}

static inline uint32x4 u8x16_u32x4(uint8x16 x) {
  uint32x4 ret;
  ret._[0] = (uint32_t)(((uint32_t) x._[ 0]) << 24) + (((uint32_t) x._[ 1]) << 16) + (((uint32_t) x._[ 2]) << 8) + ((uint32_t) x._[ 3]);
  ret._[1] = (uint32_t)(((uint32_t) x._[ 4]) << 24) + (((uint32_t) x._[ 5]) << 16) + (((uint32_t) x._[ 6]) << 8) + ((uint32_t) x._[ 7]);
  ret._[2] = (uint32_t)(((uint32_t) x._[ 8]) << 24) + (((uint32_t) x._[ 9]) << 16) + (((uint32_t) x._[10]) << 8) + ((uint32_t) x._[11]);
  ret._[3] = (uint32_t)(((uint32_t) x._[12]) << 24) + (((uint32_t) x._[13]) << 16) + (((uint32_t) x._[14]) << 8) + ((uint32_t) x._[15]);
  return ret;
}

static inline uint8x16 u8t_u8x16(uint8_t * x) {
  // no check for actually 16 -> assume external interface checks this
  uint8x16 ret;
  ret._[ 0] = x[ 0]; ret._[ 1] = x[ 1]; ret._[ 2] = x[ 2]; ret._[ 3] = x[ 3];
  ret._[ 4] = x[ 4]; ret._[ 5] = x[ 5]; ret._[ 6] = x[ 6]; ret._[ 7] = x[ 7];
  ret._[ 8] = x[ 8]; ret._[ 9] = x[ 9]; ret._[10] = x[10]; ret._[11] = x[11];
  ret._[12] = x[12]; ret._[13] = x[13]; ret._[14] = x[14]; ret._[15] = x[15];
  return ret;
}

static inline uint8x16 u8x24_u8x16_f(uint8x24 x) {
  uint8x16 ret;
  ret._[ 0] = x._[ 0]; ret._[ 1] = x._[ 1]; ret._[ 2] = x._[ 2]; ret._[ 3] = x._[ 3];
  ret._[ 4] = x._[ 4]; ret._[ 5] = x._[ 5]; ret._[ 6] = x._[ 6]; ret._[ 7] = x._[ 7];
  ret._[ 8] = x._[ 8]; ret._[ 9] = x._[ 9]; ret._[10] = x._[10]; ret._[11] = x._[11];
  ret._[12] = x._[12]; ret._[13] = x._[13]; ret._[14] = x._[14]; ret._[15] = x._[15];
  return ret;
}

static inline uint8x16 u8x24_u8x16_l(uint8x24 x) {
  uint8x16 ret;
  ret._[ 0] = x._[16]; ret._[ 1] = x._[17]; ret._[ 2] = x._[18]; ret._[ 3] = x._[19];
  ret._[ 4] = x._[20]; ret._[ 5] = x._[21]; ret._[ 6] = x._[22]; ret._[ 7] = x._[23];
  ret._[ 8] = 0x00000; ret._[ 9] = 0x00000; ret._[10] = 0x00000; ret._[11] = 0x00000;
  ret._[12] = 0x00000; ret._[13] = 0x00000; ret._[14] = 0x00000; ret._[15] = 0x00000;
  return ret;
}

static inline uint32x4 u8x24_u32x4_rem(uint8x24 x, uint32x2 * r) {
  *r = u8x16_u32x2(u8x24_u8x16_l(x));
  return u8x16_u32x4(u8x24_u8x16_f(x));
}

static inline uint8x16 u8x32_u8x16_drpl(uint8x32 x) {
  uint8x16 ret;
  ret._[ 0] = x._[16]; ret._[ 1] = x._[17]; ret._[ 2] = x._[18]; ret._[ 3] = x._[19];
  ret._[ 4] = x._[20]; ret._[ 5] = x._[21]; ret._[ 6] = x._[22]; ret._[ 7] = x._[23];
  ret._[ 8] = x._[24]; ret._[ 9] = x._[25]; ret._[10] = x._[26]; ret._[11] = x._[27];
  ret._[12] = x._[28]; ret._[13] = x._[29]; ret._[14] = x._[30]; ret._[15] = x._[31];
  return ret;
}

static inline uint8x16 u8x32_u8x16_drpf(uint8x32 x) {
  uint8x16 ret;
  ret._[ 0] = x._[ 0]; ret._[ 1] = x._[ 1]; ret._[ 2] = x._[ 2]; ret._[ 3] = x._[ 3];
  ret._[ 4] = x._[ 4]; ret._[ 5] = x._[ 5]; ret._[ 6] = x._[ 6]; ret._[ 7] = x._[ 7];
  ret._[ 8] = x._[ 8]; ret._[ 9] = x._[ 9]; ret._[10] = x._[10]; ret._[11] = x._[11];
  ret._[12] = x._[12]; ret._[13] = x._[13]; ret._[14] = x._[14]; ret._[15] = x._[15];
  return ret;
}

static inline void u8x32_u32_4_split2(uint32x4 * f, uint32x4 * s, uint8x32 x) {
  *f = u8x16_u32x4(u8x32_u8x16_drpl(x));
  *s = u8x16_u32x4(u8x32_u8x16_drpf(x));
}

static inline void * flatten_uint8(uint8_t * x, int sz) {
  uint8x16 * ret16 = NULL; uint8x24 * ret24 = NULL; uint8x32 * ret32 = NULL; 
  switch (sz) {
    case 16:
      ret16 = (uint8x16 *) x;
      return ret16;
    case 24:
      ret24 = (uint8x24 *) x;
      return ret24;
    case 32:
      ret32 = (uint8x32 *) x;
      return ret32;
    default:
      // error!
      return NULL;
  }
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
static inline void __gen_aes_192_expAssist(uint32x4 prev, uint32x4 next1, uint32x4 next2, uint32x4 next3, uint32x2 * temp, uint32_t rcon1, uint32_t rcon2) {
  next1._[0] = temp->_[0];
  next1._[1] = temp->_[1];
  next1._[2] = sub_word(rot_word(next1._[1])) ^ rcon1 ^  prev._[0];
  next1._[3] = sub_word(rot_word(next1._[2])) ^ rcon1 ^  prev._[1];

  next2._[0] = sub_word(rot_word(next1._[3])) ^ rcon1 ^  prev._[2];
  next2._[1] = sub_word(rot_word(next2._[0])) ^ rcon1 ^  prev._[3];
  next2._[2] = sub_word(rot_word(next2._[1])) ^ rcon1 ^ next1._[0];
  next2._[3] = sub_word(rot_word(next2._[2])) ^ rcon1 ^ next1._[1];

  next3._[0] = sub_word(rot_word(next2._[3])) ^ rcon2 ^ next1._[2];
  next3._[1] = sub_word(rot_word(next3._[0])) ^ rcon2 ^ next1._[3];
  next3._[2] = sub_word(rot_word(next3._[1])) ^ rcon2 ^ next2._[0];
  next3._[3] = sub_word(rot_word(next3._[2])) ^ rcon2 ^ next2._[1];

  temp->_[0] = sub_word(rot_word(next3._[3])) ^ rcon2 ^ next2._[2];
  temp->_[1] = sub_word(rot_word(temp->_[0])) ^ rcon2 ^ next2._[3];
}

static void __gen_key_expansion_192(uint32x4 * schedule[13], uint8x24 encKey) {
  uint32x2 temp;
  
  (*schedule)[0] = u8x24_u32x4_rem(encKey, &temp);
  __gen_aes_192_expAssist((*schedule)[0], (*schedule)[ 1], (*schedule)[ 2], (*schedule)[ 3], &temp, 0x01, 0x02);
  __gen_aes_192_expAssist((*schedule)[3], (*schedule)[ 4], (*schedule)[ 5], (*schedule)[ 6], &temp, 0x04, 0x08);
  __gen_aes_192_expAssist((*schedule)[6], (*schedule)[ 7], (*schedule)[ 8], (*schedule)[ 9], &temp, 0x10, 0x20);
  __gen_aes_192_expAssist((*schedule)[9], (*schedule)[10], (*schedule)[11], (*schedule)[12], &temp, 0x40, 0x80);
}

#pragma mark - Key Management: 256
static inline void __gen_aes_256_expAssist(uint32x4 prev1, uint32x4 prev2, uint32x4 next1, uint32x4 next2, uint32_t rcon, int half) {
  next1._[0] = sub_word(rot_word(prev2._[3])) ^ rcon ^ prev1._[0];
  next1._[1] = sub_word(rot_word(next1._[0])) ^ rcon ^ prev1._[1];
  next1._[2] = sub_word(rot_word(next1._[1])) ^ rcon ^ prev1._[2];
  next1._[3] = sub_word(rot_word(next1._[2])) ^ rcon ^ prev1._[3];
  if (half) { return; }
  next2._[0] = sub_word(rot_word(next1._[3])) ^ rcon ^ prev2._[0];
  next2._[1] = sub_word(rot_word(next2._[0])) ^ rcon ^ prev2._[1];
  next2._[2] = sub_word(rot_word(next2._[1])) ^ rcon ^ prev2._[2];
  next2._[3] = sub_word(rot_word(next2._[2])) ^ rcon ^ prev2._[3];
}

static void __gen_key_expansion_256(uint32x4 * schedule[15], uint8x32 encKey) {
	uint32x4 dummy = {0,0,0,0};
  
  u8x32_u32_4_split2(&(*schedule)[0], &(*schedule)[1], encKey);
  __gen_aes_256_expAssist((*schedule)[ 0], (*schedule)[ 1], (*schedule)[ 2], (*schedule)[ 3], 0x01, 0);
  __gen_aes_256_expAssist((*schedule)[ 2], (*schedule)[ 3], (*schedule)[ 4], (*schedule)[ 5], 0x02, 0);
  __gen_aes_256_expAssist((*schedule)[ 4], (*schedule)[ 5], (*schedule)[ 6], (*schedule)[ 7], 0x04, 0);
  __gen_aes_256_expAssist((*schedule)[ 6], (*schedule)[ 7], (*schedule)[ 8], (*schedule)[ 9], 0x08, 0);
  __gen_aes_256_expAssist((*schedule)[ 8], (*schedule)[ 9], (*schedule)[10], (*schedule)[11], 0x10, 0);
  __gen_aes_256_expAssist((*schedule)[10], (*schedule)[11], (*schedule)[12], (*schedule)[13], 0x20, 0);
  __gen_aes_256_expAssist((*schedule)[12], (*schedule)[12], (*schedule)[14],           dummy, 0x40, 1);
}

inline uint32x4 * load_key_expansion(uint8_t * key, AESKeyMode keymode) {
  uint32x4 * keySchedule = malloc((keymode + 1) * sizeof(uint32x4));
  switch(keymode) {
    case aes_128:
      __gen_key_expansion_128(&keySchedule, *((uint8x16 *)flatten_uint8(key, 16)));
      break;
    case aes_192:
      __gen_key_expansion_192(&keySchedule, *((uint8x24 *)flatten_uint8(key, 24)));
      break;
    case aes_256:
      __gen_key_expansion_256(&keySchedule, *((uint8x32 *)flatten_uint8(key, 32)));
      break;
    default:
      fprintf(stderr, "[%s] %s", __FILE__, aes_mode_error());
			exit(EXIT_FAILURE);
			break;
  }

  return keySchedule;
}

#pragma mark - Encryption and Decryption Internal Core
/*!
  @brief One round of AES encryption using the round specific key

  Takes the 16 byte data word and encrypts it - dependent on the round - with a specific passed key.
  It is up to the implementation to ensure that the right key is passed for the correct round. This
  function is thus "dumb" and does not know what round it is. Also note that the function edits the
  pointer directly to streamline linking in the overall AES encryption process.

  @warning For the last round, do not use this function use: __gen_aes_encl()

  @param data The pointer to the 16 bytes of data to encrypt
  @param key The specific key, based on the round, to encrypt with
 */
static inline void __gen_aes_encs(uint8x16 * data, uint8x16 key) {
	// process: sub -> shift -> mix -> addrkey
	uint8_t * raw = data->_;
	sub_bytes(raw); shift_rows(raw); mix_columns(raw);
	// addrkey
	raw[ 0] = raw[ 0] ^ key._[ 0]; raw[ 1] = raw[ 1] ^ key._[ 1]; raw[ 2] = raw[ 2] ^ key._[ 2];
	raw[ 3] = raw[ 3] ^ key._[ 3]; raw[ 4] = raw[ 4] ^ key._[ 4]; raw[ 5] = raw[ 5] ^ key._[ 5];
	raw[ 6] = raw[ 6] ^ key._[ 6]; raw[ 7] = raw[ 7] ^ key._[ 7]; raw[ 8] = raw[ 8] ^ key._[ 8];
	raw[ 9] = raw[ 9] ^ key._[ 9]; raw[10] = raw[10] ^ key._[10]; raw[11] = raw[11] ^ key._[11];
	raw[12] = raw[12] ^ key._[12]; raw[13] = raw[13] ^ key._[13]; raw[14] = raw[14] ^ key._[14];
	raw[15] = raw[15] ^ key._[15];
}
/*!
 @brief One round of AES decryption using the round specific key
 
 Takes the 16 byte data word and encrypts it - dependent on the round - with a specific passed key.
 It is up to the implementation to ensure that the right key is passed for the correct round. This
 function is thus "dumb" and does not know what round it is. Also note that the function edits the
 pointer directly to streamline linking in the overall AES encryption process.
 
 @warning For the last round, do not use this function use: __gen_aes_decf()
 
 @param data The pointer to the 16 bytes of data to encrypt
 @param key The specific key, based on the round, to encrypt with
 */
static inline void __gen_aes_decs(uint8x16 * data, uint8x16 key) {
	// process: xor -> mix -> shift -> sub
	uint8_t * raw = data->_;
	// xor
	raw[ 0] = raw[ 0] ^ key._[ 0]; raw[ 1] = raw[ 1] ^ key._[ 1]; raw[ 2] = raw[ 2] ^ key._[ 2];
	raw[ 3] = raw[ 3] ^ key._[ 3]; raw[ 4] = raw[ 4] ^ key._[ 4]; raw[ 5] = raw[ 5] ^ key._[ 5];
	raw[ 6] = raw[ 6] ^ key._[ 6]; raw[ 7] = raw[ 7] ^ key._[ 7]; raw[ 8] = raw[ 8] ^ key._[ 8];
	raw[ 9] = raw[ 9] ^ key._[ 9]; raw[10] = raw[10] ^ key._[10]; raw[11] = raw[11] ^ key._[11];
	raw[12] = raw[12] ^ key._[12]; raw[13] = raw[13] ^ key._[13]; raw[14] = raw[14] ^ key._[14];
	raw[15] = raw[15] ^ key._[15];
	// mix & shift & sub
	inv_mix_columns(raw); inv_shift_rows(raw); inv_sub_bytes(raw);
}

static inline void __gen_aes_decf(uint8x16 * data, uint8x16 key) {
	// process: xor -> shift -> sub
	uint8_t * raw = data->_;
	
}
