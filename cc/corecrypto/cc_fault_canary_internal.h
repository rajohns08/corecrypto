/* Copyright (c) (2019,2020) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef corecrypto_cc_fault_canary_internal_h
#define corecrypto_cc_fault_canary_internal_h

/*!
@function   cc_fault_canary_set
@abstract   Set the output `fault_canary_out` to the value `fault_canary` if the two inputs are equal.

@param fault_canary_out  Output fault canary value
@param fault_canary      Fault canary for a specific operation (e.g. CCEC_FAULT_CANARY for ECC signing)
@param nbytes            Byte length of inputs in1 and in2
@param in1               Input one
@param in2               Input two
*/
void cc_fault_canary_set(cc_fault_canary_t fault_canary_out, const cc_fault_canary_t fault_canary, size_t nbytes, const uint8_t *in1, const uint8_t *in2);

#endif /* corecrypto_cc_fault_canary_internal_h */
