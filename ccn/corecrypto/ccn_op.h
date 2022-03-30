/* Copyright (c) (2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef ccop_h
#define ccop_h

#include <corecrypto/ccn.h>

//ccn files are related to the funcations that take arrays as input.
//this file is not working with arrays. It is exceptionally called ccn_op.h
//to be consistent with the file naming in the ccn directory
//cc_unit is defined in ccn.h. When cc_unit definition is moved to the cc directory (perhaps)
//this file can be moved and renamed.

// These are corecrypto constant-time primitive operations,
// and are meant to be used inside corecrypto.
//
// all ccop_*() functions return 0 or ~0 i.e. 0xFFFFFF....

//returns the most significant bit in the form of 0 or ~0

/*!
 @function ccop_msb(a)
 @param a The operand
 @return 0xFFF...F if most significant bit of a is 1 and 0 otherwise.
 @brief Constant time computation of a's most signficiant bit, assuming x >> b is implemented in constant time.
  */
CC_INLINE cc_unit ccop_msb(cc_unit a){
    return (cc_unit)((cc_int)a >> (CCN_UNIT_BITS-1));
}

/*!
 @function ccop_is_zero(a)
 @param a The operand
 @return 0xFFF...F if a==0 and 0 otherwise.
 @brief Constant time check if a is equal to 0.
 */
CC_INLINE cc_unit ccop_is_zero(cc_unit a){
    return ccop_msb(~a & (a - 1));
}

/*!
 @function ccop_eq(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a==b and 0 otherwise.
 @brief Constant time check if a is equal to b.
 */
CC_INLINE cc_unit ccop_eq(cc_unit a, cc_unit b){
    return ccop_is_zero(a^b);
}

/*!
 @function ccop_neq(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a!=b and 0 otherwise.
 @brief Constant time check if a is not equal to b.
 */
CC_INLINE cc_unit ccop_neq(cc_unit a, cc_unit b){
    return ~ccop_eq(a, b);
}

/*!
 @function ccop_lt(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a < b and 0 otherwise.
 @brief Constant time check if a is less than b.
 */
CC_INLINE cc_unit ccop_lt(cc_unit a, cc_unit b){
    return ccop_msb(a^ ((a^b) | ((a-b)^a)) );
}

/*!
 @function ccop_gt(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a>b and 0 otherwise.
 @brief Constant time check if a is greater than b.
 */
CC_INLINE cc_unit ccop_gt(cc_unit a, cc_unit b){
    return ccop_lt(b, a);
}

/*!
 @function ccop_lte(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a<=b and 0 otherwise.
 @brief Constant time check if a is less than or equal to b.
 */
CC_INLINE cc_unit ccop_lte(cc_unit a, cc_unit b){
    return (~ccop_gt(a, b));
}

/*!
 @function ccop_gte(a, b)
 @param a The left operand
 @param b The right operand
 @return 0xFFF...F if a>=b and 0 otherwise.
 @brief Constant time check if a is greater than or equal to b.
 */
CC_INLINE cc_unit ccop_gte(cc_unit a, cc_unit b){
    return (~ccop_lt(a, b));
}

/*!
 @function ccop_sel(sel, a, b)
 @param sel The selector; must be either 0xFF..FF or 0x00..00
 @param a The left operand
 @param b The right operand
 @return  sel ? a : b;
 @brief Constant time implementation of sel ? a : b, assuming sel is 0x00..00 or 0xFF..FF
 */
//The sel input must be either the output of a ccop_*() function or 0/~0
CC_INLINE cc_unit ccop_sel(cc_unit sel, cc_unit a, cc_unit b){
    return (~sel & b) | (sel & a);
}

#endif /* ccop_h */
