//
//  AESni.h
//  SimpleCrypt
//
//  Created by Developer on 31.08.18.
//  Copyright © 2018 jniegsch. All rights reserved.
//

/*!
 @file AESgen.h
 
 The header file for the AES encryption (basic as well as CBC and CTR mode) implemented in general c
 
 @updated 08-31-2018
 @version 0.0.1
 @author Jan Niegsch
 */
#ifndef AESgen_h
#define AESgen_h

#include <stdlib.h>
#include <stdio.h>

#include "AESCore.h"

#pragma mark - Convenience Definitions
#if !defined(__arm__) && !defined(__aarch32__) && !defined(__arm64__) && !defined(__aarch64__) && !defined(_M_ARM)

typedef struct uint8x16_t {
  uint8_t _[16];
} uint8x16;

typedef struct uint8x24_t {
  uint8_t _[24];
} uint8x24;

typedef struct uint8x32_t {
  uint8_t _[32];
} uint8x32;

typedef struct uint32x2_t {
  uint32_t _[2];
} uint32x2;

typedef struct uint32x4_t {
  uint32_t _[4];
} uint32x4;

#endif

#endif /* AESgen_h */