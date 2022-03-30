/* Copyright (c) (2015,2016,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */


#ifndef ccder_priv_h
#define ccder_priv_h

/*!
 @function   ccder_decode_uint_skip_leading_zeroes
 @abstract   Return the pointer on the most significant byte
            Caller must ensure there is no overread (der + *len < der_end) prior
            to calling this.
 Per ITU-T Rec. X.690 (07/2002), section 8.3 "If the contents octets of an integer value 
 encoding consist of more than one octet, then the bits of the first octet
 and bit 8 of the second octet, Shall not all be ones and shall not be zero".
 Here we only allow unsigned integers.

 @param      der        Beginning of input DER buffer
 @param      len        Pointer to the length. Update to the number of remaining byte
                        it may contain 0 as input/output.

 @result     Pointer on the most significant byte
            NULL is too many leading zeroes
 */

CC_NONNULL((1, 2))
CC_INLINE const uint8_t *ccder_decode_uint_skip_leading_zeroes(
                                                     size_t *len,
                                                     const uint8_t *der)
{
    if (!(*len)) {
        // ISO/IEC 8825-1:2003 (E) 8.3.1 The encoding of an integer value shall be primitive
        // The contents octets shall consist of one or more octets.
        return NULL;
    }
    // Sign
    if (der[0] & 0x80) {
        // Negative value, not authorized for unsigned integer
        return NULL;
    }
    // Leading byte
    if (der[0] == 0) {
        (*len)--;
        der++;

        // At this point, we expect the most significant bit set
        if ((*len)
            && !(der[0] & 0x80)) return NULL;
    }

    return der;
}

#endif /* ccder_priv_h */
