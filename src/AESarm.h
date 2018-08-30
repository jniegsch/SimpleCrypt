//
//  AESarm.h
//  
//
//  Created by Developer on 24.08.18.
//
// * * * * * * * * * * * * * * * * * * * *
// Compile with -march=armv8-a+crypto
// * * * * * * * * * * * * * * * * * * * * 

/*!
 @file AESarm.h
 
 The header file for the AES encryption (basic as well as CBC and CTR mode) implemented with ARM Intrinsics
 
 @updated 08-24-2018
 @version 0.0.1
 @author Jan Niegsch
 */

#ifndef AESarm_h
#define AESarm_h

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "AESCore.h"
#include <arm_neon.h>

// check arm
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
	#if defined(__ARM_NEON) || defined(__MSC_VER) || defined(_M_ARM)
		#include <armintr.h>
		#include <arm_neon.h>
	#endif
	#if defined(_M_ARM64)
		#include <arm64intr.h>
		#include <arm64_neon.h>
	#endif
	#if defined(__GNUC__) && !defined(__apple_build_version__)
		// apparently not supported on apple sas: https://github.com/noloader/AES-Intrinsics/blob/master/aes-arm.c
		#if defined(__ARM_ACL) || defined(__ARM_FEATURE_CRYPTO)
			#include <arm_acl.h>
		#endif
	#endif
#endif

#pragma mark - Key Management Internals
/*!
 @group Key Management Internals
 */

/*!
 @typedef AESKeyMode
 
 @brief An enum setting the key mode.
 
 This enum allows to set which key mode for AES is being uesd: either 128 bits, 192 bits, or 256 bits. By setting this also the rounds of AES are defined
 
 Possible values for the key mode and what it specifies:
 - aes_128: @code AES-128 [key = 128bits, AES rounds = 10] @endcode
 - aes_192: @code AES-192 [key = 192bits, AES rounds = 12] @endcode
 - aes_256: @code AES-256 [key = 256bits, AES rounds = 14] @endcode
 */
typedef enum {
	aes_128 = 10,
	aes_192 = 12,
	aes_256 = 14
} AESKeyMode;

#pragma mark - Key Management Core
/*!
	@name Key Management Core
	ARM Intrinsic implemetation of the key loading sequence
 */
/// @{
/*!
	@brief Intrinsic implementation of the key loading (expansion) sequence

	Takes an externally definied epoch key (usually passed by the user or generated
	using a PRG). Based on the key mode chosen (AES-128, AES-192 or AES-256) the specific 
	sequence is run and the key schedule is returned. 

	@see AESKeyMode for information regarding the modes. 

	@warning Only call this loader on ARM CPUs.
	@information If you require CTR or CBC mode, you do not need to call this function, both
	implementations take care of the key expansion internally.

	@param key A `16 btye` userkey used for the key expansion
	@param keymode The AES version to use

	@returns The generated key schedule, where each key are 4 32 byte words (`uint32x4_t`) 
	and the overall length depends on the amount of rounds defined by the AES version.
 */
__attribute__((visibility("hidden"), nonnull(1), target("arch=armv8-a+crypto")))
extern inline uint32x4_t * load_key_expansion(uint8_t * key, AESKeyMode keymode);
/// @}

#pragma mark - Encryption and Decryption Core
/*!
	@name Encryption and Decryption Core
	This group of functions handle the encryption and decryption defined by the AES NIST standard
 */
///@{
/*!
	@brief Encrypts the passed data using AES

	Encrypts the data passed to the function using the AES algorithm defined by NIST. 
	@warning The encryption is done directly on the passed data array which must be 128 bits (16 bytes)
 
 @code
 char * fullMessage = ...;
 uint8_t * userKey = ...; // 128bits using AES-128
 uint8x16_t * keySchedule = load_key_expansion(userKey, aes_128);
 // Encrypt the first 16 bytes AES-128
 aes_arm_enc((uint8x16_t *)fullMessage[0], keySchedule, aes_128);
 @endcode

 @param data The data to encrypt
 @param keySchedule The key schedule to use
 @param keymode The key mode specifying the key schedule length and AES mode

 */
__attribute__((visibility("hidden"), nonnull(1, 2), target("arch=armv8-a+crypto")))
extern inline void aes_arm_enc(uint8x16_t * data, uint8x16_t * keySchedule, AESKeyMode keymode);

/*!
	@brief Decrypts the data using AES implemented directly on the Intel Chip
 
 	Decrypts the data passed with the specified Key Schedule through AES using the key length set. The function is implemented using intel Intrinsics for greater performance.
 
 	@warning The decryption is done directly on the passed data array which must be 128 bits (16 bytes)
 
 	@code
 	uint8_t * fullCipher = ...;
 	uint8_t * userKey = ...; // 128bits using AES-128
 	uint8x16_t * keySchedule = load_key_expansion(userKey, aes_128);
 	// Decrypt the first 16 bytes AES-128
 	aes_arm_dec((uint8x16_t *)fullCipher[0], keySchedule, aes_128);
 	@endcode
 
 	@param data The data to decrypt
 	@param keySchedule The key schedule to use
 	@param keymode The key mode specifying the key schedule length and AES mode
 */
__attribute__((visibility("hidden"), nonnull(1, 2), target("arch=armv8-a+crypto")))
extern inline void aes_arm_dec(uint8x16_t * data, uint8x16_t * keySchedule, AESKeyMode keymode);

#endif /* AESarm_h */
