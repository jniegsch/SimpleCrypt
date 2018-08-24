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

static void check_adv_SIMD_enabled(void) {
	uin
}
