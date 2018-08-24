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

#include <stdint.h>
#include <stdio.h>
#include <arm_neon.h>

// check arm
#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
	#if defined(__GNUC__)
		#include <stdint.h>
		#include <stdio.h>
	#endif
	#if defined(__ARM_NEON) || defined(__MSC_VER) || defined(_M_ARM)
		#include <armintr.h>
		#include <arm_neon.h>
	#endif
	#if defined(_M_ARM64)
		#include <arm64intr.h>
		#include <arm64_neon.h>
	#endif
	#if defined(__GNUC__) && !defined(__apple_build_version__)
		// apparently not supported on apple sys: https://github.com/noloader/AES-Intrinsics/blob/master/aes-arm.c
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



#endif /* AESarm_h */
