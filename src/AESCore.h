//
//  AESCore.h
//  
//
//  Created by Jan Niegsch on 26.08.18.
//
// * * * * * * * * * * * * * * * * * * * *
// Compile with -fvisibility=hidden
// * * * * * * * * * * * * * * * * * * * * 

/*!
 @file AESCore.h
 
 The header file of the library core which defines essentials used in all implementations 
 
 @updated 08-26-2018
 @version 0.0.1
 @author Jan Niegsch
 */

#ifndef AESCore_h
#define AESCore_h

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#pragma mark - Core Errors
/*!
  @brief Returns the standardized error message for a wrong AES key mode

  Returns the standardized error message for when a wrong AES key mode was passed. Message is:
  @code
  Fatal Error: an invalid aes mode was passed.
               > Even though Rijndael supports several lengths of key bits, AES is defined to only support 128, 192, or 256 bits
  @endcode

  @returns A string for the specific error.
 */
__attribute__((visibility("hidden")))
char * aes_mode_error(void);

#pragma mark - S Box Internals
/*!
  @brief Returns a byte transformed by the S-box

  Transforms the input byte using the AES S-box

  @param byte The input byte to transform using the S-box

  @returns A byte that is defined by the S-box when given a byte
 */
__attribute__((visibility("hidden")))
uint8_t s_box(uint8_t byte);
/*!
  @brief Returns a byte transformed by the inverse S-box

  Transforms the input byte using the AES inverse S-box

  @param byte The input byte to transform using the inverse S-box

  @returns A byte that is defined by the inverse S-box when given a byte
 */
__attribute__((visibility("hidden")))
uint8_t inv_s_box(uint8_t byte);

#pragma mark - Sub and Rot Words
/*!
  @brief Applies the SubWord of the AES algorithm

  The function takes a word (which is `4 bytes`) and applies the S-box to each byte to produce an output word.

  @param inp The input word (`32 bits` or `4 bytes`)

  @returns A word resulting from the S-box transformation on the input word
 */
__attribute__((visibility("hidden")))
extern inline uint32_t sub_word(uint32_t inp);
/*!
  @brief Applies the RotWord of the AES algorithm

  The function takes a word (which is `4 bytes`) and performs a cyclic permutation.
  The permutation is as follows:
  @code
  [a_0, a_1, a_2, a_3] -> [a_1, a_2, a_3, a_0]
  @endcode

  @param inp The input word (`32 bits` or `4 bytes`)

  @returns A word resulting from the permutation on the input word
 */
extern inline uint32_t rot_word(uint32_t inp);

#endif /* AESCore_h */
