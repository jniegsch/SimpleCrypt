//
//  AESni.h
//  IIAES
//
//  Created by Developer on 23.08.18.
//  Copyright © 2018 jniegsch. All rights reserved.
//

/*!
 @file AESni.h
 
 The header file for the AES encryption (basic as well as CBC and CTR mode) implemented with Intel Intrinsics
 
 @updated 08-23-2018
 @version 0.0.1
 @author Jan Niegsch
 */

#ifndef AESni_h
#define AESni_h

#ifdef __has_include
	#if __has_include(<stdio.h>)
		#include <stdio.h>
		#include <stdlib.h>
		#include "AESCore.h"
	#endif
	# if __has_include(<wmmintrin.h>)
		#include <wmmintrin.h>
		#include <emmintrin.h>
		#include <smmintrin.h>
		#define intel_active
	#endif
#endif

#ifdef intel_active
#pragma mark - Key Management Internals
/*!
 @name Key Management Internals
 Definitions pertaining to the Key Management (expansion)
 */
///@{
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
///@}

#pragma mark - Encryption and Decryption Core
/*!
	@name Encryption and Decryption Core
	The core functions of AES encryption and decryption
 */
///@{
/*!
 @brief Encrypts the data using AES implemented directly on the Intel Chip
 
 Encrypts the data passed with the specified Key Schedule through AES using the key length set. The function is implemented using intel Intrinsics for greater performance.
 
 @warning The encryption is done directly on the passed data array which must be 128 bits (16 bytes)
 
 @code
 char * fullMessage = ...;
 uint8_t * userKey = ...; // 128bits using AES-128
 __m128i * keySchedule = loadKeyExpansion(userKey, aes_128);
 // Encrypt the first 16 bytes AES-128
 aes_ni_enc((__m128i *)fullMessage[0], keySchedule, aes_128);
 @endcode

 @param data The data to encrypt
 @param key_schedule The key schedule to use
 @param keymode The key mode specifying the key schedule length and AES mode
 */
__attribute__((visibility("hidden"), nonnull(1, 2), target("aes")))
extern inline void aes_ni_enc(__m128i * data, __m128i * key_schedule, AESKeyMode keymode);

/*!
 @brief Decrypts the data using AES implemented directly on the Intel Chip
 
 Decrypts the data passed with the specified Key Schedule through AES using the key length set. The function is implemented using intel Intrinsics for greater performance.
 
 @warning The decryption is done directly on the passed data array which must be 128 bits (16 bytes)
 
 @code
 uint8_t * fullCipher = ...;
 uint8_t * userKey = ...; // 128bits using AES-128
 __m128i * keySchedule = loadKeyExpansion(userKey, aes_128);
 // Decrypt the first 16 bytes AES-128
 aes_ni_dec((__m128i *)fullCipher[0], keySchedule, aes_128);
 @endcode
 
 @param data The data to decrypt
 @param key_schedule The key schedule to use
 @param keymode The key mode specifying the key schedule length and AES mode
 */
__attribute__((visibility("hidden"), nonnull(1, 2), target("aes")))
extern inline void aes_ni_dec(__m128i * data, __m128i * key_schedule, AESKeyMode keymode);
///@}

#pragma mark - CBC Core
/*!
	@name CBC Core
	The functions related to encrypting and decrypting using the Cipher Block Chain approach.
 */
///@{
/*!
 @brief Encrypts the data using Cipher Block Chain (CBC) AES implemented directly on the Intel Chip
 
 Encrypts the passed input data using CBC. The function is implemented using intel Intrinsics for greater performance.
 
 @note CBC requires padding, which this function assumes you have already done
 @warning The input length <b>must</b> be a multiple of 16 (use padding if necessary) . No checks are run to ensure input, ivec, or epoch key are the correct lengths
 
 
 Possible values for the key mode and what it specifies:
 - aes_128: @code AES-128 [key = 128bits, AES rounds = 10] @endcode
 - aes_192: @code AES-192 [key = 192bits, AES rounds = 12] @endcode
 - aes_256: @code AES-256 [key = 256bits, AES rounds = 14] @endcode
 
 @param inpt The data to encrypt using AES and CBC
 @param outt A pointer to a `malloc`ed location where the encrypted data will be written
 @param ivec The IV (Initial Vector) to be used for CBC
 @param mlength The length of the input message [in bytes] which is also the output (cipher) message length
 @param epoch_key The key (either defined by the user or generated by the software) that will be used for the key expansion to make the key schedule
 @param keymode The AES mode (also defines the key length and number of rounds) [see the possible values above]
 
 @see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 */
__attribute__((visibility("hidden"), nonnull(1, 2, 3, 5), target("aes")))
void aes_cbc_ni_enc(uint8_t * inpt, uint8_t * outt, uint8_t * ivec, unsigned long mlength, uint8_t * epoch_key, AESKeyMode keymode);

/*!
 @brief Decrypts the data using Cipher Block Chain (CBC) AES implemented directly on the Intel Chip
 
 Decrypts the passed input data using CBC.  The function is implemented using intel Intrinsics for greater performance.
 
 @note CBC requires padding, which this function assumes you will remove yourself after returning
 @warning The input length <b>must</b> be a multiple of 16. No checks are run to ensure input, ivec, or epoch key are the correct lengths
 
 Possible values for the key mode and what it specifies:
 - aes_128: @code AES-128 [key = 128bits, AES rounds = 10] @endcode
 - aes_192: @code AES-192 [key = 192bits, AES rounds = 12] @endcode
 - aes_256: @code AES-256 [key = 256bits, AES rounds = 14] @endcode
 
 @param inpt The data to decrypt using AES and CBC
 @param outt A pointer to a `malloc`ed location where the decrypted data will be written
 @param ivec The IV (Initial Vector) to be used for CBC decryption
 @param clength The length of the input cipher [in bytes] which is also the output (message) length
 @param epoch_key The key (passed by the user) that will be used for the key expansion to make the key schedule to decrypt
 @param keymode The AES mode (also defines the key length and number of rounds) [see the possible values above]
 
 @see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
 */
__attribute__((visibility("hidden"), nonnull(1, 2, 3, 5), target("aes")))
void aes_cbc_ni_dec(uint8_t * inpt, uint8_t * outt, uint8_t * ivec, unsigned long clength, uint8_t * epoch_key, AESKeyMode keymode);
///@}

#pragma mark - CTR Core
/*!
	@name CTR Core
	The functions related to encrypting and decrypting using the CounTeR approach.
 */
///@{
/*!
 @brief Encrypts or Decrypts the data using Counter Mode (CTR) AES implemented directly on the Intel Chip
 
 Encrypts or Decrypts the passed input data using CTR. The function is implemented using intel Intrinsics for greater performance.
 
 @note Due to the nature of CTR, encryption and decryption are the same so that does not have to be specified. If a non encrypted message is passed it will be encrypted, if an encrypted message is passed it will be decrypted
 @warning No checks are run to ensure input, ivec, or epoch key are the correct lengths
 
 Possible values for the key mode and what it specifies:
 - aes_128: @code AES-128 [key = 128bits, AES rounds = 10] @endcode
 - aes_192: @code AES-192 [key = 192bits, AES rounds = 12] @endcode
 - aes_256: @code AES-256 [key = 256bits, AES rounds = 14] @endcode
 
 @param inpt The data to decrypt/decrypt using AES and CBC
 @param outt A pointer to a `malloc`ed location where the decrypted/encrypted data will be written
 @param ivec The IV (Initial Vector) to be used during the CTR process
 @param mlength The length of the input [in bytes] which is also the output length
 @param epoch_key The key (passed by the user) that will be used for the key expansion to make the key schedule to encrypt/decrypt
 @param keymode The AES mode (also defines the key length and number of rounds) [see the possible values above]
 
 @see https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
 */
__attribute__((visibility("hidden"), nonnull(1, 2, 3, 5), target("aes")))
void aes_ctr_ni(uint8_t * inpt, uint8_t * outt, uint8_t * ivec, unsigned long mlength, uint8_t * epoch_key, AESKeyMode keymode);
///@}

#endif /* protection */
#endif /* AESni_h */
